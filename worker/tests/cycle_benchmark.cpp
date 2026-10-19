// Development-only diagnostic. Trusted control modes deliberately have no
// sandbox; they are never reachable from Worker or its executor protocol.
#include <saga/worker.hpp>
#include "internal.hpp"

#include <fcntl.h>
#include <linux/landlock.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iostream>
#include <memory>
#include <numeric>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using Json = nlohmann::json;
using Clock = std::chrono::steady_clock;

std::string document(const std::string& path) {
    std::ifstream input(path);
    if (!input) throw std::runtime_error("cannot open benchmark input");
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

std::size_t read_file(const std::string& path) {
    const int descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) throw std::runtime_error("benchmark read failed");
    std::array<char, 8192> bytes{};
    std::size_t total = 0;
    for (;;) {
        const auto count = read(descriptor, bytes.data(), bytes.size());
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { close(descriptor); throw std::runtime_error("benchmark read failed"); }
        if (!count) break;
        total += static_cast<std::size_t>(count);
    }
    close(descriptor);
    return total;
}

void reap(pid_t child) {
    int status;
    while (waitpid(child, &status, 0) < 0)
        if (errno != EINTR) throw std::runtime_error("benchmark wait failed");
    if (!WIFEXITED(status) || WEXITSTATUS(status))
        throw std::runtime_error("benchmark child failed");
}

void control_child(const std::string& path, bool fresh_image) {
    const pid_t child = fork();
    if (child < 0) throw std::runtime_error("benchmark fork failed");
    if (!child) {
        if (fresh_image) {
            char name[] = "saga-cycle-benchmark";
            char mode[] = "--control-child";
            char* arguments[] = {name, mode, const_cast<char*>(path.c_str()), nullptr};
            char* environment[] = {nullptr};
            execve("/proc/self/exe", arguments, environment);
            _exit(127);
        }
        try { _exit(read_file(path) ? 0 : 1); }
        catch (...) { _exit(1); }
    }
    reap(child);
}

std::int64_t resident_kib() {
    std::ifstream input("/proc/self/status");
    std::string line;
    while (std::getline(input, line))
        if (line.rfind("VmRSS:", 0) == 0) return std::stoll(line.substr(6));
    throw std::runtime_error("cannot inspect benchmark RSS");
}

double cpu_ms(const rusage& usage) {
    return static_cast<double>(usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) * 1000.0 +
        static_cast<double>(usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / 1000.0;
}

double percentile(const std::vector<double>& ordered, double fraction) {
    return ordered.at(static_cast<std::size_t>(std::ceil(fraction * static_cast<double>(ordered.size()))) - 1);
}

Json read_capability(const std::string& path) {
    return {{"tool", "read_file"}, {"resource", "benchmark"}, {"operation", "read"},
        {"arguments", {{"resource", "benchmark"}}}, {"execution", {{"path", path}}},
        {"sandbox", {{"paths", {{{"path", path}, {"access", "read"}}}}, {"tcp_ports", Json::array()}}}};
}

bool can_read(const std::string& path) {
    const int descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) return false;
    close(descriptor);
    return true;
}

void restrict_reads(const std::string& path) {
    landlock_ruleset_attr attributes{};
    attributes.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
    const int ruleset = static_cast<int>(syscall(SYS_landlock_create_ruleset, &attributes, sizeof(attributes), 0));
    const int target = open(path.c_str(), O_PATH | O_CLOEXEC);
    if (ruleset < 0 || target < 0) throw std::runtime_error("Landlock control setup failed");
    landlock_path_beneath_attr rule{};
    rule.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
    rule.parent_fd = target;
    const bool failed = syscall(SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH, &rule, 0) < 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 || syscall(SYS_landlock_restrict_self, ruleset, 0) < 0;
    close(target);
    close(ruleset);
    if (failed) throw std::runtime_error("Landlock control restriction failed");
}

Json invariants(const std::string& path, const std::string& other) {
    // This independent child isolates the irreversible experimental rules from
    // the diagnostic coordinator. It does not alter production sandbox code.
    const pid_t child = fork();
    if (child < 0) throw std::runtime_error("invariant fork failed");
    if (!child) {
        try {
            restrict_reads(path);
            if (!can_read(path) || can_read(other)) _exit(1);
            restrict_reads(other);
            // Layer B cannot restore rights denied by the already active A.
            _exit(!can_read(path) && !can_read(other) ? 0 : 1);
        } catch (...) { _exit(1); }
    }
    reap(child);
    const Json specification = {
        {"sandbox", {{"paths", {{{"path", path}, {"access", "read"}}}}, {"tcp_ports", Json::array()}}},
        {"attempts", {{{"kind", "read"}, {"path", path}}, {{"kind", "read"}, {"path", other}},
            {{"kind", "fork"}}, {{"kind", "exec"}}}},
    };
    const auto result = Json::parse(saga::sandbox_probe(specification.dump()));
    if (!result.value("ok", false)) throw std::runtime_error("production invariant probe failed");
    const auto& attempts = result.at("attempts");
    if (!attempts.at(0).value("ok", false) || attempts.at(1).value("ok", false) ||
        attempts.at(2).value("ok", false) || attempts.at(3).value("ok", false) ||
        attempts.at(2).at("errno") != EPERM || attempts.at(3).at("errno") != EPERM)
        throw std::runtime_error("production execution restrictions changed");
    return {{"ok", true}, {"landlock_layers_intersect", true}, {"sandbox", result}};
}
}

int main(int argc, char** argv) {
    try {
        if (argc == 3 && std::string(argv[1]) == "--control-child") return read_file(argv[2]) ? 0 : 1;
        std::string mode;
        std::string path;
        std::string other;
        std::string config_path;
        int iterations = 200;
        int warmup = 20;
        int memory_mib = 0;
        for (int index = 1; index < argc; ++index) {
            if (index + 1 >= argc) throw std::runtime_error("benchmark option requires a value");
            const std::string key = argv[index++];
            const std::string value = argv[index];
            if (key == "--mode") mode = value;
            else if (key == "--file") path = value;
            else if (key == "--other") other = value;
            else if (key == "--config") config_path = value;
            else if (key == "--iterations") iterations = std::stoi(value);
            else if (key == "--warmup") warmup = std::stoi(value);
            else if (key == "--memory-mib") memory_mib = std::stoi(value);
            else throw std::runtime_error("unknown benchmark option");
        }
        if (mode == "invariants") {
            std::cout << invariants(path, other).dump() << '\n';
            return 0;
        }
        if (iterations < 1 || iterations > 100000 || warmup < 0 || warmup > 10000 || memory_mib < 0 || memory_mib > 512)
            throw std::runtime_error("benchmark sample or allocation limit exceeded");
        if (mode != "direct" && mode != "fork_only" && mode != "fork_exec_control" &&
            mode != "sandbox_empty" && mode != "sandbox_read" && mode != "worker")
            throw std::runtime_error("unknown benchmark mode");
        const auto memory_bytes = static_cast<std::size_t>(memory_mib) * 1024 * 1024;
        auto memory = std::make_unique<unsigned char[]>(memory_bytes);
        for (std::size_t offset = 0; offset < memory_bytes; offset += 4096) memory[offset] = 0x5a;
        std::unique_ptr<saga::Worker> worker;
        if (mode == "worker") worker = std::make_unique<saga::Worker>(saga::WorkerConfig::from_json(document(config_path)));
        const auto capability = mode == "sandbox_read" ? read_capability(path) : Json();
        const Json empty = {{"sandbox", {{"paths", Json::array()}, {"tcp_ports", Json::array()}}}, {"attempts", Json::array()}};
        const std::string call = Json({{"task_id", "bench"}, {"format", "canonical"},
            {"call", {{"tool", "read_file"}, {"arguments", {{"resource", "notes"}}}}}}).dump();
        std::size_t count = 0;
        auto execute = [&] {
            if (mode == "direct") count += read_file(path);
            else if (mode == "fork_only" || mode == "fork_exec_control") control_child(path, mode == "fork_exec_control");
            else if (mode == "sandbox_empty") {
                if (!saga::detail::probe_child(empty).value("ok", false)) throw std::runtime_error("empty production sandbox failed");
            } else if (mode == "sandbox_read") {
                bool started = false;
                const auto result = saga::detail::execute_child(capability, started);
                if (!started || !result.value("ok", false) || result.at("result").at("content").get_ref<const std::string&>().size() != 4096)
                    throw std::runtime_error("production read failed");
            } else if (mode == "worker") {
                const auto result = Json::parse(worker->perform(call));
                if (!result.value("ok", false) || !result.value("executor_started", false) ||
                    result.at("result").at("content").get_ref<const std::string&>().size() != 4096)
                    throw std::runtime_error("end-to-end benchmark call failed");
            }
        };
        for (int index = 0; index < warmup; ++index) execute();
        const auto rss_before = resident_kib();
        rusage self_before{}, child_before{};
        getrusage(RUSAGE_SELF, &self_before);
        getrusage(RUSAGE_CHILDREN, &child_before);
        std::vector<double> samples;
        samples.reserve(static_cast<std::size_t>(iterations));
        const auto begin = Clock::now();
        for (int index = 0; index < iterations; ++index) {
            const auto start = Clock::now();
            execute();
            samples.push_back(std::chrono::duration<double, std::milli>(Clock::now() - start).count());
        }
        const auto elapsed_ms = std::chrono::duration<double, std::milli>(Clock::now() - begin).count();
        rusage self_after{}, child_after{};
        getrusage(RUSAGE_SELF, &self_after);
        getrusage(RUSAGE_CHILDREN, &child_after);
        auto ordered = samples;
        std::sort(ordered.begin(), ordered.end());
        std::cout << Json({{"mode", mode}, {"iterations", iterations}, {"warmup", warmup}, {"parent_extra_mib", memory_mib},
            {"landlock_abi", saga::landlock_abi()}, {"samples_ms", samples},
            {"min_ms", ordered.front()}, {"p50_ms", percentile(ordered, .5)}, {"p95_ms", percentile(ordered, .95)},
            {"p99_ms", percentile(ordered, .99)}, {"max_ms", ordered.back()},
            {"mean_ms", std::accumulate(samples.begin(), samples.end(), 0.0) / static_cast<double>(samples.size())},
            {"elapsed_ms", elapsed_ms}, {"calls_per_second", static_cast<double>(iterations) * 1000.0 / elapsed_ms},
            {"coordinator_rss_before_kib", rss_before}, {"coordinator_rss_after_kib", resident_kib()},
            {"child_max_rss_kib_including_warmup", child_after.ru_maxrss},
            {"coordinator_cpu_ms", cpu_ms(self_after) - cpu_ms(self_before)},
            {"children_cpu_ms", cpu_ms(child_after) - cpu_ms(child_before)}, {"direct_bytes_read", count}}).dump() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << Json({{"error", error.what()}}).dump() << '\n';
        return 1;
    }
}
