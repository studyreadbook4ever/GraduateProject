#include <saga/worker.hpp>
#include <nlohmann/json.hpp>

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
std::string read_document(const std::string& path) {
    std::ifstream stream(path);
    if (!stream) throw std::runtime_error("cannot read " + path);
    return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
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
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if ((arg == "--config" || arg == "--calls") && i + 1 < argc) {
                (arg == "--config" ? config_path : calls_path) = argv[++i];
            } else {
                throw std::runtime_error("usage: saga-worker --config worker.json [--calls calls.jsonl] | --probe | --sandbox-probe spec.json");
            }
        }
        if (config_path.empty()) throw std::runtime_error("--config is required");
        saga::Worker worker(saga::WorkerConfig::from_json(read_document(config_path)));
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
            failed = failed || !nlohmann::json::parse(result).value("ok", false);
        }
        return failed ? 1 : 0;
    } catch (const std::exception& error) {
        std::cerr << "saga-worker: " << error.what() << '\n';
        return 2;
    }
}
