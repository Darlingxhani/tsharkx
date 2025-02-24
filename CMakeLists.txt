cmake_minimum_required(VERSION 3.10)
project(tshark)

set(CMAKE_CXX_STANDARD 11)

# 添加头文件路径
include_directories(third_library)

add_definitions(-DNOMINMAX)

# 定义可执行文件
add_executable(tshark
        main.cpp
        tsharkManager.cpp
        third_library/loguru/loguru.cpp
        third_library/loguru/loguru.hpp
        third_library/ip2region/xdb_bench.cc
        third_library/ip2region/xdb_search.cc
        third_library/ip2region/ip2region_util.cpp
)

target_link_libraries(tshark PRIVATE ws2_32)
# 确保所有路径都是相对于项目根目录的