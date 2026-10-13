#include <saga/worker.hpp>
#include <nlohmann/json.hpp>

#include <atomic>
#include <cerrno>
#include <csignal>
#include <iostream>
#include <stdexcept>
#include <string>
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
        std::cout << "host boundary checks passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
