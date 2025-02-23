cmake_minimum_required(VERSION 3.10)
project(tshark)

set(CMAKE_CXX_STANDARD 11)

# 添加头文件路径
include_directories(third_library)

add_definitions(-DNOMINMAX)

# 定义可执行文件
add_executable(tshark
        ${PROJECT_SOURCE_DIR}/main.cpp
        ${PROJECT_SOURCE_DIR}/tsharkManager.cpp
        ${PROJECT_SOURCE_DIR}/third_library/loguru/loguru.cpp
        ${PROJECT_SOURCE_DIR}/third_library/loguru/loguru.hpp
        ${PROJECT_SOURCE_DIR}/third_library/ip2region/xdb_bench.cc
        ${PROJECT_SOURCE_DIR}/third_library/ip2region/xdb_search.cc
        ${PROJECT_SOURCE_DIR}/third_library/ip2region/ip2region_util.cpp
)

target_link_libraries(tshark PRIVATE ws2_32)
# 确保所有路径都是相对于项目根目录的