cmake_minimum_required(VERSION 3.22.1)

project(seccomp_demo)

add_library(
    seccomp_demo
    SHARED
    seccomp_demo_jni.cpp
)

find_library(log-lib log)

target_link_libraries(
    seccomp_demo
    ${log-lib}
)
