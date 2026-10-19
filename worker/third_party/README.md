# Bundled JSON parser

`nlohmann/json.hpp` is the unmodified single-header distribution of
[JSON for Modern C++ 3.12.0](https://github.com/nlohmann/json/releases/tag/v3.12.0).
Its MIT license and copyright notice are included in the header.

Source: https://raw.githubusercontent.com/nlohmann/json/v3.12.0/single_include/nlohmann/json.hpp

SHA-256: `aaf127c04cb31c406e5b04a63f1ae89369fccde6d8fa7cdda1ed4f32dfc5de63`

Bundling avoids downloading dependencies during CMake configuration. The parser
is private to the worker implementation; installed library headers do not
require it.
