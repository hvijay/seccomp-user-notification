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

# ---------------------------------------------------------------------------
# bpf_service: the BPF loader/proxy packaged as a PIE executable inside the
# APK.  Android Gradle only picks up *.so files from the CMake output dir,
# so we rename the executable to libbpf_service.so and place it there.
# Set -DLIBBPF_PREFIX=<staged-aosp-bpfdeps> to enable this target.
# ---------------------------------------------------------------------------
set(LIBBPF_PREFIX "" CACHE PATH "Prefix containing staged Android libbpf/libelf/libzstd headers and libraries")

if(LIBBPF_PREFIX AND ANDROID_ABI STREQUAL "arm64-v8a")
    add_executable(bpf_service
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../loader/src/binder_monitor_loader.c
    )
    target_include_directories(bpf_service PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../loader/compat
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../common
        ${LIBBPF_PREFIX}/include
        ${LIBBPF_PREFIX}/include/bpf
        ${LIBBPF_PREFIX}/include/linux
    )
    target_link_libraries(bpf_service PRIVATE
        ${LIBBPF_PREFIX}/lib/libbpf.a
        ${LIBBPF_PREFIX}/lib/libelf.a
        ${LIBBPF_PREFIX}/lib/libzstd.a
        z
    )
    target_compile_options(bpf_service PRIVATE -fPIE)
    target_link_options(bpf_service PRIVATE -pie)
    set_target_properties(bpf_service PROPERTIES
        OUTPUT_NAME "libbpf_service"
        SUFFIX ".so"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}"
    )
endif()
