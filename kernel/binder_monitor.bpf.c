#include "../common/shared_types.h"
#include "compat/binder_uapi_min.h"
#include "compat/bpf_helpers_min.h"

#define ARM64_NR_IOCTL 29

/* ARM64 MTE tags live in bits 56-63. Strip before passing to bpf_probe_read_user. */
static __always_inline binder_uintptr_t untag_ptr(binder_uintptr_t ptr)
{
    return ptr & 0x00FFFFFFFFFFFFFFULL;
}

/* pt_regs and seccomp_data are defined in compat/bpf_helpers_min.h */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} target_cgroup_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct binder_txn_info);
} scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct binder_txn_info);
} txn_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 12);
    __type(key, __u32);
    __type(value, __u64);
} debug_counters SEC(".maps");

static __always_inline __u64 min_u64(__u64 a, __u64 b)
{
    return a < b ? a : b;
}

static __always_inline void bump_counter(__u32 index)
{
    __u64 *value = bpf_map_lookup_elem(&debug_counters, &index);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
}

SEC("kprobe/do_seccomp")
int binder_monitor(struct pt_regs *ctx)
{
    __u32 zero = 0;
    __u64 *target_pid = 0;
    __u64 pid_tgid;
    __u64 uid_gid;
    unsigned int cmd = 0;
    unsigned long arg = 0;
    struct binder_write_read bwr = {};
    struct binder_transaction_data txn = {};
    struct binder_txn_info *info;
    __u32 bcmd = 0;
    __u32 capture_size = 0;
    __u32 current_pid = 0;
    struct seccomp_data sd = {};

    bump_counter(0);

    if ((int)PT_REGS_PARM1(ctx) != ARM64_NR_IOCTL) {
        return 0;
    }

    bump_counter(1);

    target_pid = bpf_map_lookup_elem(&target_cgroup_map, &zero);
    if (!target_pid || *target_pid == 0) {
        return 0;
    }

    pid_tgid = bpf_get_current_pid_tgid();
    current_pid = (__u32)(pid_tgid >> 32);
    if ((__u64)current_pid != *target_pid) {
        bump_counter(7);
        return 0;
    }

    bump_counter(2);
    if (bpf_probe_read_kernel(&sd, sizeof(sd), (const void *)PT_REGS_PARM2(ctx)) == 0) {
        bump_counter(3);
    } else if (bpf_probe_read_kernel(&sd, sizeof(sd), (const void *)PT_REGS_PARM3(ctx)) == 0) {
        bump_counter(4);
    } else if (bpf_probe_read_kernel(&sd, sizeof(sd), (const void *)ctx->regs[3]) == 0) {
        bump_counter(5);
    } else if (bpf_probe_read_kernel(&sd, sizeof(sd), (const void *)ctx->regs[4]) == 0) {
        bump_counter(6);
    } else {
        bump_counter(7);
        return 0;
    }

    cmd = (unsigned int)sd.args[1];
    arg = (unsigned long)sd.args[2];

    bpf_printk("binder_monitor: pid match! pid=%u cmd=0x%x BINDER_WRITE_READ=0x%x",
               current_pid,
               cmd, (__u32)BINDER_WRITE_READ);
    if (cmd != (__u32)BINDER_WRITE_READ) {
        return 0;
    }

    info = bpf_map_lookup_elem(&scratch, &zero);
    if (!info) {
        return 0;
    }
    info->pid = 0;
    info->tid = 0;
    info->uid = 0;
    info->timestamp_ns = 0;
    info->target_handle = 0;
    info->code = 0;
    info->flags = 0;
    info->data_size = 0;
    info->offsets_size = 0;
    info->is_reply = 0;
    info->parcel_truncated = 0;
    info->parcel_captured = 0;

    if (bpf_probe_read_user(&bwr, sizeof(bwr), (const void *)arg) != 0) {
        bump_counter(3);
        return 0;
    }
    bump_counter(4);

    if (bwr.write_size < sizeof(bcmd) || bwr.write_buffer == 0) {
        bump_counter(5);
        return 0;
    }

    if (bpf_probe_read_user(&bcmd, sizeof(bcmd), (const void *)untag_ptr(bwr.write_buffer)) != 0) {
        bump_counter(6);
        return 0;
    }
    bump_counter(7);

    if (bcmd != (__u32)BC_TRANSACTION && bcmd != (__u32)BC_REPLY) {
        return 0;
    }

    if (bwr.write_size < sizeof(bcmd) + sizeof(txn)) {
        return 0;
    }

    if (bpf_probe_read_user(&txn, sizeof(txn),
                            (const void *)(untag_ptr(bwr.write_buffer) + sizeof(bcmd))) != 0) {
        bump_counter(10);
        return 0;
    }
    bump_counter(8);

    uid_gid = bpf_get_current_uid_gid();

    info->pid = (__u32)(pid_tgid >> 32);
    info->tid = (__u32)pid_tgid;
    info->uid = (__u32)uid_gid;
    info->timestamp_ns = bpf_ktime_get_ns();
    info->target_handle = txn.target.handle;
    info->code = txn.code;
    info->flags = txn.flags;
    info->data_size = (__u32)txn.data_size;
    info->offsets_size = (__u32)txn.offsets_size;
    info->is_reply = (bcmd == (__u32)BC_REPLY) ? 1 : 0;
    info->parcel_truncated = txn.data_size > PARCEL_CAPTURE_SIZE ? 1 : 0;

    capture_size = (__u32)min_u64(txn.data_size, PARCEL_CAPTURE_SIZE);
    info->parcel_captured = capture_size;

    if (capture_size > 0 && txn.data.ptr.buffer != 0) {
        binder_uintptr_t buf_addr = untag_ptr(txn.data.ptr.buffer);
        if (bpf_probe_read_user(info->raw_parcel, capture_size,
                                (const void *)buf_addr) == 0) {
            info->parcel_captured = capture_size;
        } else {
            info->parcel_captured = 0;
        }
    }

    if (bpf_map_update_elem(&txn_map, &info->tid, info, BPF_ANY) != 0) {
        bump_counter(9);
        return 0;
    }
    bump_counter(11);
    bpf_printk("binder_monitor: recorded txn tid=%u bcmd=0x%x", info->tid, bcmd);
    return 0;
}
