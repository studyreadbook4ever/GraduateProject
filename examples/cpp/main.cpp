#include <saga/worker.hpp>
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    try {
        std::ifstream input(argv[1]);
        if (!input) throw std::runtime_error("configuration unavailable");
        const std::string config{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
        saga::Worker worker(saga::WorkerConfig::from_json(config));
        // A retry must reuse the operation ID for the same logical action.
        const auto receipt = worker.perform(R"({"task_id":"demo","format":"canonical","operation_id":"cpp-demo-001","call":{"tool":"read_file","arguments":{"resource":"notes"}}})");
        std::cout << receipt << '\n';
        return nlohmann::json::parse(receipt).at("ok").get<bool>() ? 0 : 1;
    } catch (const std::exception&) {
        std::cerr << "saga example could not initialize\n";
        return 2;
    }
}
