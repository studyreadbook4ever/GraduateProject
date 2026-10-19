#include <saga/worker.hpp>
#include <nlohmann/json.hpp>

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdexcept>
#include <string>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace {
const std::string specification = R"({"sandbox":{"paths":[],"tcp_ports":[]},"attempts":[{"kind":"udp_socket"}]})";

bool fails_before_fork(const std::string& message) {
    try { saga::sandbox_probe(specification); }
    catch (const std::runtime_error& error) {
        return std::string(error.what()).find(message) != std::string::npos;
    }
    return false;
}
}

int main() {
    try {
        // Direct C++ construction must reject invalid path bytes just like the
        // JSON config API, before fopen/curl can truncate a name at NUL.
        for (const auto field : {&saga::WorkerConfig::ca_certificate, &saga::WorkerConfig::client_certificate,
             &saga::WorkerConfig::client_key, &saga::WorkerConfig::provider_public_key}) {
            for (const auto& invalid : {std::string{}, std::string("prefix\0suffix", 13)}) {
                saga::WorkerConfig config{"https://127.0.0.1:1", "ca", "cert", "key", "public", "agent"};
                config.*field = invalid;
                bool refused = false;
                try { saga::Worker worker(std::move(config)); }
                catch (const std::runtime_error& error) {
                    refused = std::string(error.what()).find("without NUL") != std::string::npos;
                }
                if (!refused) throw std::runtime_error("direct C++ invalid path was not rejected before IO");
            }
        }
        std::atomic<bool> running{false};
        {
            std::jthread extra_thread([&](std::stop_token stop) {
                running.store(true);
                while (!stop.stop_requested()) std::this_thread::yield();
            });
            while (!running.load()) std::this_thread::yield();
            if (!fails_before_fork("single-threaded"))
                throw std::runtime_error("multithreaded library host was accepted");
        }
        struct sigaction ignored{};
        ignored.sa_handler = SIG_IGN;
        sigemptyset(&ignored.sa_mask);
        struct sigaction previous{};
        if (sigaction(SIGCHLD, &ignored, &previous) != 0)
            throw std::runtime_error("cannot change SIGCHLD in test");
        const bool rejected = fails_before_fork("default SIGCHLD");
        sigaction(SIGCHLD, &previous, nullptr);
        if (!rejected) throw std::runtime_error("automatic child reaping was accepted");

        // A new PID alone does not prove clean memory: fork preserves this
        // private mapping, including coordinator keys and previous-call data.
        const auto page = static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
        void* secret = MAP_FAILED;
        for (std::uintptr_t slot = 16; slot < 48 && secret == MAP_FAILED; ++slot) {
            secret = mmap(reinterpret_cast<void*>(slot << 30), page, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        }
        if (secret == MAP_FAILED) throw std::runtime_error("cannot reserve parent secret mapping");
        const std::string sentinel = "coordinator-key-and-prior-call-data-remain-in-parent-only";
        std::memcpy(secret, sentinel.data(), sentinel.size());
        unsigned char resident = 0;
        if (mincore(secret, page, &resident) != 0) throw std::runtime_error("parent secret is not mapped");
        if (setenv("SAGA_HOST_SECRET", sentinel.c_str(), 1) != 0)
            throw std::runtime_error("cannot set parent environment marker");
        const int neutral = open("/dev/null", O_RDWR | O_CLOEXEC);
        const int inherited = fcntl(neutral, F_DUPFD, 100);
        close(neutral);
        if (inherited < 0) throw std::runtime_error("cannot reserve inherited parent descriptor");
        const nlohmann::json clean_specification = {
            {"sandbox", {{"paths", nlohmann::json::array()}, {"tcp_ports", nlohmann::json::array()}}},
            {"attempts", {
                {{"kind", "memory_mapping"}, {"address", reinterpret_cast<std::uintptr_t>(secret)}},
                {{"kind", "environment"}, {"name", "SAGA_HOST_SECRET"}},
                {{"kind", "descriptor"}, {"fd", inherited}},
                {{"kind", "environment"}, {"name", "LD_LIBRARY_PATH"}},
                {{"kind", "descriptor"}, {"fd", 0}},
                {{"kind", "descriptor"}, {"fd", 1}},
                {{"kind", "descriptor"}, {"fd", 2}},
            }},
        };
        // Repeat from the same library host to cover previous-call reuse.
        for (int invocation = 0; invocation < 2; ++invocation) {
            const auto clean = nlohmann::json::parse(saga::sandbox_probe(clean_specification.dump()));
            if (!clean.at("ok").get<bool>()) throw std::runtime_error("fresh-image probe failed");
            const auto& attempts = clean.at("attempts");
            if (attempts.at(0).at("ok").get<bool>() || attempts.at(0).at("errno") != ENOMEM ||
                attempts.at(1).at("ok").get<bool>() || attempts.at(1).at("errno") != ENOENT ||
                attempts.at(2).at("ok").get<bool>() || attempts.at(2).at("errno") != EBADF ||
                attempts.at(3).at("ok").get<bool>() || attempts.at(3).at("errno") != ENOENT)
                throw std::runtime_error("executor retained coordinator memory, environment, or descriptors");
            for (std::size_t index = 4; index < attempts.size(); ++index)
                if (!attempts.at(index).at("ok").get<bool>())
                    throw std::runtime_error("executor lost neutral standard streams");
        }
        if (std::memcmp(secret, sentinel.data(), sentinel.size()) != 0 ||
            !std::getenv("SAGA_HOST_SECRET") || fcntl(inherited, F_GETFD) < 0)
            throw std::runtime_error("executor damaged parent state");
        close(inherited);
        unsetenv("SAGA_HOST_SECRET");
        munmap(secret, page);

        // Policy may prohibit executable memfds. Refuse execution in that
        // environment: falling back to a fork-only handler leaks parent memory.
        const pid_t policy_child = fork();
        if (policy_child < 0) throw std::runtime_error("policy test fork failed");
        if (policy_child == 0) {
            sock_filter rules[] = {
                BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_memfd_create, 0, 1),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            };
            sock_fprog program{static_cast<unsigned short>(sizeof(rules) / sizeof(rules[0])), rules};
            if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
                prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) _exit(1);
            try { saga::sandbox_probe(specification); }
            catch (const std::runtime_error&) {
                int status;
                _exit(waitpid(-1, &status, WNOHANG) == -1 && errno == ECHILD ? 0 : 1);
            }
            _exit(1);
        }
        int policy_status;
        while (waitpid(policy_child, &policy_status, 0) < 0) {
            if (errno != EINTR) throw std::runtime_error("cannot reap policy test child");
        }
        if (!WIFEXITED(policy_status) || WEXITSTATUS(policy_status) != 0)
            throw std::runtime_error("executor did not fail closed when memfd execution was prohibited");

        // A host file-size limit also covers the coordinator's executor memfd.
        // Keep SIGXFSZ at its default action: writing past the limit would kill
        // this test process before the API could report a graceful refusal.
        const pid_t limited_host = fork();
        if (limited_host < 0) throw std::runtime_error("file-size test fork failed");
        if (limited_host == 0) {
            struct sigaction default_action{};
            default_action.sa_handler = SIG_DFL;
            sigemptyset(&default_action.sa_mask);
            rlimit limit{};
            if (sigaction(SIGXFSZ, &default_action, nullptr) < 0 ||
                getrlimit(RLIMIT_FSIZE, &limit) < 0) _exit(1);
            limit.rlim_cur = 1;
            if (setrlimit(RLIMIT_FSIZE, &limit) < 0) _exit(1);
            try { saga::sandbox_probe(specification); }
            catch (const std::runtime_error&) {
                int child_status;
                _exit(waitpid(-1, &child_status, WNOHANG) == -1 && errno == ECHILD ? 0 : 1);
            }
            _exit(1);
        }
        int limited_status;
        while (waitpid(limited_host, &limited_status, 0) < 0) {
            if (errno != EINTR) throw std::runtime_error("cannot reap file-size test child");
        }
        if (!WIFEXITED(limited_status) || WEXITSTATUS(limited_status) != 0)
            throw std::runtime_error("executor preparation killed a host with a small file-size limit");

        // Exercise result-pipe relocation and neutral stdio without affecting
        // the CTest runner's descriptors.
        const pid_t test_child = fork();
        if (test_child < 0) throw std::runtime_error("test fork failed");
        if (test_child == 0) {
            close(STDIN_FILENO); close(STDOUT_FILENO); close(STDERR_FILENO);
            try {
                const auto result = nlohmann::json::parse(saga::sandbox_probe(specification));
                const auto& attempt = result.at("attempts").at(0);
                _exit(result.at("ok").get<bool>() && !attempt.at("ok").get<bool>() &&
                    attempt.at("errno").get<int>() == EPERM ? 0 : 1);
            } catch (...) { _exit(1); }
        }
        int status;
        while (waitpid(test_child, &status, 0) < 0) {
            if (errno != EINTR) throw std::runtime_error("cannot reap test child");
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
            throw std::runtime_error("closed-stdio host sandbox failed");
        std::cout << "host boundary and fresh-image memory checks passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
