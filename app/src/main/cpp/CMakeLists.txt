cmake_minimum_required(VERSION 3.22.1)
project(rasp_native LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 生产加固应开启 -fvisibility=hidden、去掉符号表、加控制流混淆；demo 保留可读性
add_library(rasp_native SHARED
        rasp_native.cpp
        raw_syscall.cpp
        scanners.cpp)

target_compile_options(rasp_native PRIVATE
        -Wall -Wextra -fstack-protector-strong
        -fvisibility=hidden)

find_library(log-lib log)
target_link_libraries(rasp_native ${log-lib})

# 主机自检目标（非 Android）：仅编译与 JNI 无关的扫描器，喂样例数据验证逻辑
if(NOT ANDROID)
    add_executable(rasp_host_test host_test.cpp scanners.cpp raw_syscall.cpp)
    target_include_directories(rasp_host_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
endif()
