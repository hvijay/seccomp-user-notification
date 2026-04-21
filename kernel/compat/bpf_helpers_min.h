#ifndef SECCOMP_BINDER_MONITOR_BPF_HELPERS_MIN_H
#define SECCOMP_BINDER_MONITOR_BPF_HELPERS_MIN_H

#include <linux/types.h>

#define SEC(name) __attribute__((section(name), used))
#undef __always_inline
#define __always_inline inline __attribute__((always_inline))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif

enum {
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
};

enum {
    BPF_ANY = 0,
};

static void *(* const bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (* const bpf_map_update_elem)(void *map, const void *key,
                                          const void *value, __u64 flags) = (void *)2;
static __u64 (* const bpf_ktime_get_ns)(void) = (void *)5;
static __u64 (* const bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (* const bpf_get_current_uid_gid)(void) = (void *)15;
static __u64 (* const bpf_get_current_cgroup_id)(void) = (void *)80;
static long (* const bpf_probe_read_user)(void *dst, __u32 size,
                                          const void *unsafe_ptr) = (void *)112;
static long (* const bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *)6;

#define bpf_printk(fmt, ...)                                        \
    ({                                                              \
        static const char ____fmt[] = fmt;                          \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);  \
    })

char LICENSE[] SEC("license") = "GPL";

#endif
