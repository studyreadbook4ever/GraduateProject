#pragma once

#include <memory>
#include <string>

namespace saga {

// The coordinator owns credentials; a fresh restricted child runs each admitted
// capability. Construct and use Worker on a single-threaded process with the
// default SIGCHLD disposition; the coordinator owns and reaps its child.
struct WorkerConfig {
    std::string provider_url;
    std::string ca_certificate;
    std::string client_certificate;
    std::string client_key;
    std::string provider_public_key;
    std::string agent_id;

    static WorkerConfig from_json(const std::string& document);
};

class Worker {
public:
    explicit Worker(WorkerConfig config);
    ~Worker();
    Worker(Worker&&) noexcept;
    Worker& operator=(Worker&&) noexcept;
    Worker(const Worker&) = delete;
    Worker& operator=(const Worker&) = delete;

    // Takes {task_id, format, call}. Returns a JSON object with ok and result
    // or error. Admission errors never run a handler.
    std::string perform(const std::string& call_record);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Reports the actual running kernel ABI, or -1 when Landlock is unavailable.
int landlock_abi() noexcept;

// Local diagnostic API. Its specification cannot execute arbitrary commands.
// Takes {sandbox:{paths:[{path,access}],tcp_ports:[port]},attempts:[...]},
// where access is read/write and attempts select fixed diagnostic operations.
// Always uses the production sandbox.
std::string sandbox_probe(const std::string& specification);

} // namespace saga
