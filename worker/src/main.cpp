#include <saga/worker.hpp>
#include <nlohmann/json.hpp>

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
std::string read_document(const std::string& path) {
    if (path.empty() || path.find('\0') != std::string::npos)
        throw std::runtime_error("invalid document path");
    std::ifstream stream(path);
    if (!stream) throw std::runtime_error("cannot read " + path);
    return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}

void emit_failure(const std::string& receipt) {
    const auto value = nlohmann::json::parse(receipt);
    if (value.value("ok", false)) return;
    nlohmann::json event = {{"event", "worker_failure"}};
    for (const auto* field : {"call_id", "phase", "executor_phase", "error_code", "request_id", "execution_id",
                             "executor_started", "admission_uncertain", "completion_recorded", "http_status"})
        if (value.contains(field)) event[field] = value.at(field);
    std::cerr << event.dump() << '\n' << std::flush;
}
}

int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--probe") {
            const int abi = saga::landlock_abi();
            std::cout << "{\"landlock_abi\":" << abi
                      << ",\"required_abi\":9,\"supported\":"
                      << (abi >= 9 ? "true" : "false") << "}\n";
            return abi >= 9 ? 0 : 1;
        }
        if (argc == 3 && std::string(argv[1]) == "--sandbox-probe") {
            std::cout << saga::sandbox_probe(read_document(argv[2])) << '\n';
            return 0;
        }
        std::string config_path;
        std::string calls_path;
        std::string operation_id;
        bool revoke = false;
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if ((arg == "--config" || arg == "--calls" || arg == "--operation") && i + 1 < argc) {
                auto& value = arg == "--config" ? config_path : arg == "--calls" ? calls_path : operation_id;
                value = argv[++i];
                if (value.empty()) throw std::runtime_error("empty option value");
            } else if (arg == "--revoke") {
                revoke = true;
            } else {
                throw std::runtime_error("usage: saga-worker --config worker.json [--calls calls.jsonl] | --probe | --sandbox-probe spec.json");
            }
        }
        if (config_path.empty()) throw std::runtime_error("--config is required");
        if (revoke && !calls_path.empty()) throw std::runtime_error("--revoke does not accept --calls");
        if (!operation_id.empty() && (revoke || !calls_path.empty()))
            throw std::runtime_error("--operation must be used separately");
        saga::Worker worker(saga::WorkerConfig::from_json(read_document(config_path)));
        if (!operation_id.empty()) {
            const auto result = worker.operation_status(operation_id);
            std::cout << result << '\n' << std::flush;
            emit_failure(result);
            return nlohmann::json::parse(result).value("ok", false) ? 0 : 1;
        }
        if (revoke) {
            const auto result = worker.revoke();
            std::cout << result << '\n' << std::flush;
            emit_failure(result);
            return nlohmann::json::parse(result).value("ok", false) ? 0 : 1;
        }
        std::ifstream calls;
        std::istream* input = &std::cin;
        if (!calls_path.empty()) {
            calls.open(calls_path);
            if (!calls) throw std::runtime_error("cannot read calls file");
            input = &calls;
        }
        std::string line;
        bool failed = false;
        while (std::getline(*input, line)) {
            if (line.empty()) continue;
            const auto result = worker.perform(line);
            std::cout << result << '\n' << std::flush;
            emit_failure(result);
            failed = failed || !nlohmann::json::parse(result).value("ok", false);
        }
        return failed ? 1 : 0;
    } catch (const std::exception&) {
        // Configuration/parser exceptions can quote private paths or input.
        std::cerr << "{\"event\":\"worker_failure\",\"phase\":\"initialize\","
                     "\"error_code\":\"worker_initialization_failed\"}\n";
        return 2;
    }
}
