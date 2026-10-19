cmake_minimum_required(VERSION 3.20)
project(SagaConsumer LANGUAGES CXX)
find_package(Saga CONFIG REQUIRED)
add_executable(saga-example main.cpp)
# The example owns its receipt parser; Saga::worker exports no JSON dependency.
target_include_directories(saga-example PRIVATE ../../worker/third_party)
target_link_libraries(saga-example PRIVATE Saga::worker)
