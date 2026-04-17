cmake_minimum_required(VERSION 3.22.1)

project(seccomp_policy)

add_library(
    seccomp_policy
    SHARED
    seccomp_policy_jni.cpp
)

find_library(log-lib log)

target_link_libraries(
    seccomp_policy
    ${log-lib}
)
