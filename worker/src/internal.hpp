#pragma once

#include <nlohmann/json.hpp>

namespace saga::detail {
using Json = nlohmann::json;
Json execute_child(const Json& capability, bool& executor_started);
Json probe_child(const Json& specification);
// Private fixed-FD entry point for the embedded fresh-image executor.
int executor_main() noexcept;
}
