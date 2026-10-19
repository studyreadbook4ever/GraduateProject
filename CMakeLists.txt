cmake_minimum_required(VERSION 3.20)
project(SagaCapabilities VERSION 0.1.0 LANGUAGES CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "SAGA worker requires Linux Landlock ABI 9 or newer")
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(SQLite3 REQUIRED)
if(NOT TARGET SQLite3::SQLite3)
    add_library(SQLite3::SQLite3 ALIAS SQLite::SQLite3)
endif()

add_library(saga_worker worker/src/worker.cpp worker/src/sandbox.cpp)
add_library(Saga::worker ALIAS saga_worker)
set_target_properties(saga_worker PROPERTIES EXPORT_NAME worker)
set_target_properties(saga_worker PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_features(saga_worker PUBLIC cxx_std_20)
target_include_directories(saga_worker PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/worker/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE worker/third_party worker/src)
target_link_libraries(saga_worker PRIVATE OpenSSL::Crypto CURL::libcurl SQLite3::SQLite3 ${CMAKE_DL_LIBS})
target_compile_options(saga_worker PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

# Embed the exact executor image so static/shared consumers and relocated
# installations use the same trusted helper without searching PATH or a host
# executable directory.
add_executable(saga-executor worker/src/executor_main.cpp worker/src/sandbox.cpp)
# The embedded ELF executes from a memfd, so $ORIGIN and build-tree RPATHs
# cannot identify an installed dependency. The coordinator supplies only the
# canonical directory of the SQLite DSO that it has already loaded.
set_target_properties(saga-executor PROPERTIES SKIP_BUILD_RPATH TRUE INSTALL_RPATH "")
target_compile_features(saga-executor PRIVATE cxx_std_20)
target_compile_definitions(saga-executor PRIVATE SAGA_EXECUTOR_ONLY)
target_include_directories(saga-executor PRIVATE worker/include worker/third_party worker/src)
target_link_libraries(saga-executor PRIVATE SQLite3::SQLite3)
target_compile_options(saga-executor PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
set(executor_header "${CMAKE_CURRENT_BINARY_DIR}/generated/executor_image.hpp")
add_custom_command(OUTPUT "${executor_header}"
    COMMAND ${CMAKE_COMMAND} "-DINPUT=$<TARGET_FILE:saga-executor>" "-DOUTPUT=${executor_header}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed-executor.cmake.in"
    DEPENDS saga-executor "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed-executor.cmake.in"
    VERBATIM)
target_sources(saga_worker PRIVATE "${executor_header}")
target_include_directories(saga_worker PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")

add_executable(saga-worker worker/src/main.cpp)
target_include_directories(saga-worker PRIVATE worker/third_party)
target_link_libraries(saga-worker PRIVATE Saga::worker)
if(BUILD_SHARED_LIBS)
    # The installed CLI must find its own shared library after relocation,
    # without requiring LD_LIBRARY_PATH or a system-wide ldconfig update.
    file(RELATIVE_PATH saga_library_from_bin
        "${CMAKE_INSTALL_FULL_BINDIR}" "${CMAKE_INSTALL_FULL_LIBDIR}")
    set_property(TARGET saga-worker APPEND PROPERTY INSTALL_RPATH
        "$ORIGIN/${saga_library_from_bin}")
endif()

install(TARGETS saga_worker saga-worker EXPORT SagaTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY worker/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES LICENSE DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/saga-cap)
install(FILES worker/third_party/nlohmann/LICENSE
    DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/saga-cap/nlohmann)
install(EXPORT SagaTargets NAMESPACE Saga:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Saga)
configure_package_config_file(cmake/SagaConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/SagaConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Saga)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/SagaConfigVersion.cmake
    VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/SagaConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/SagaConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Saga)

include(CTest)
if(BUILD_TESTING)
    find_package(Threads REQUIRED)
    add_test(NAME landlock-abi COMMAND saga-worker --probe)
    add_executable(saga-worker-host-test worker/tests/host_boundary.cpp)
    target_include_directories(saga-worker-host-test PRIVATE worker/third_party)
    target_link_libraries(saga-worker-host-test PRIVATE Saga::worker Threads::Threads)
    add_test(NAME sandbox-host-boundary COMMAND saga-worker-host-test)
    add_executable(saga-cycle-benchmark worker/tests/cycle_benchmark.cpp)
    target_include_directories(saga-cycle-benchmark PRIVATE worker/third_party worker/src)
    target_link_libraries(saga-cycle-benchmark PRIVATE Saga::worker)
endif()
