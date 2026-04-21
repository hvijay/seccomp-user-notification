cmake_minimum_required(VERSION 3.16)
project(binder_monitor_loader C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT ANDROID)
  message(WARNING "This project is intended to be built with the Android NDK toolchain.")
endif()

set(LIBBPF_PREFIX "" CACHE PATH "Prefix containing staged Android libbpf/libelf/libzstd headers and libraries")
set(LIBBPF_LIBRARY "bpf" CACHE STRING "Path to Android libbpf static/shared library, or library name if toolchain resolves it")
find_library(LOG_LIBRARY log REQUIRED)

set(BPF_DEP_INCLUDE_DIRS
  ${CMAKE_CURRENT_SOURCE_DIR}/compat
)

if(LIBBPF_PREFIX)
  list(APPEND BPF_DEP_INCLUDE_DIRS
    ${LIBBPF_PREFIX}/include
    ${LIBBPF_PREFIX}/include/bpf
    ${LIBBPF_PREFIX}/include/linux
  )
  set(BPF_LINK_LIBRARIES
    ${LIBBPF_PREFIX}/lib/libbpf.a
    ${LIBBPF_PREFIX}/lib/libelf.a
    ${LIBBPF_PREFIX}/lib/libzstd.a
    z
    ${LOG_LIBRARY}
  )
else()
  set(BPF_LINK_LIBRARIES
    ${LIBBPF_LIBRARY}
    ${LOG_LIBRARY}
  )
endif()

add_executable(binder_monitor_loader
  src/binder_monitor_loader.c
)
target_include_directories(binder_monitor_loader PRIVATE
  ${BPF_DEP_INCLUDE_DIRS}
  ${CMAKE_CURRENT_SOURCE_DIR}/../common
)
target_link_libraries(binder_monitor_loader PRIVATE
  ${BPF_LINK_LIBRARIES}
)
