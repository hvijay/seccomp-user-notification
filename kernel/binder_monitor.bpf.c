#include "../common/shared_types.h"
#include "compat/binder_uapi_min.h"
#include "compat/bpf_helpers_min.h"

#define MAX_UTF16_CHARS 64
#define ARM64_NR_IOCTL 29

/* ARM64 MTE tags live in bits 56-63. Strip before passing to bpf_probe_read_user. */
static __always_inline binder_uintptr_t untag_ptr(binder_uintptr_t ptr)
{
    return ptr & 0x00FFFFFFFFFFFFFFULL;
}

struct trace_event_raw_sys_enter_min {
    __u64 common;
    long id;
    unsigned long args[6];
};

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

static __always_inline __u64 min_u64(__u64 a, __u64 b)
{
    return a < b ? a : b;
}

static __always_inline __u32 align4(__u32 value)
{
    return (value + 3U) & ~3U;
}

static __always_inline int user_read_u32(binder_uintptr_t base, __u32 limit, __u32 offset,
                                         __u32 *out)
{
    if (offset + sizeof(*out) > limit) {
        return -1;
    }
    return bpf_probe_read_user(out, sizeof(*out), (const void *)(untag_ptr(base) + offset));
}

static __always_inline __u32 read_string16_from_user(binder_uintptr_t base, __u32 limit,
                                                     __u32 offset, char *out, __u32 out_len)
{
    __u32 utf16_len = 0;
    __u32 i;
    __u32 next_offset;

    if (out_len == 0) {
        return offset;
    }
    out[0] = '\0';

    if (user_read_u32(base, limit, offset, &utf16_len) != 0) {
        return offset;
    }
    offset += sizeof(__u32);

    if (utf16_len == (__u32)-1) {
        return offset;
    }

    for (i = 0; i < out_len - 1 && i < MAX_UTF16_CHARS; i++) {
        __u16 ch = 0;
        __u32 char_offset;

        if (i >= utf16_len) {
            break;
        }

        char_offset = offset + (i * sizeof(__u16));
        if (char_offset + sizeof(ch) > limit) {
            break;
        }
        if (bpf_probe_read_user(&ch, sizeof(ch), (const void *)(untag_ptr(base) + char_offset)) != 0) {
            break;
        }

        if (ch == 0) {
            break;
        }
        out[i] = (ch >= 0x20 && ch < 0x7f) ? (char)ch : '?';
    }

    out[i < out_len ? i : out_len - 1] = '\0';
    next_offset = offset + ((__u32)utf16_len * sizeof(__u16));
    return align4(next_offset);
}

static __always_inline void parse_parcel_header(struct binder_txn_info *info,
                                                binder_uintptr_t parcel_base)
{
    __u32 offset = 0;

    if (user_read_u32(parcel_base, info->data_size, offset, &info->strict_mode) != 0) {
        return;
    }
    offset += sizeof(__u32);

    if (user_read_u32(parcel_base, info->data_size, offset, &info->work_source_uid) != 0) {
        return;
    }
    offset += sizeof(__u32);

    offset = read_string16_from_user(parcel_base, info->data_size, offset,
                                     info->interface, sizeof(info->interface));
    info->payload_start = offset;
}

static __always_inline void parse_known_intent_fields(struct binder_txn_info *info,
                                                      binder_uintptr_t parcel_base)
{
    __u32 offset = info->payload_start;

    info->intent.action[0] = '\0';
    info->intent.uri[0] = '\0';
    info->intent.package_name[0] = '\0';
    info->intent.component_pkg[0] = '\0';
    info->intent.component_class[0] = '\0';
    info->intent.flags = 0;

    if (info->code != TRANSACTION_startActivity &&
        info->code != TRANSACTION_sendBroadcast &&
        info->code != TRANSACTION_startService &&
        info->code != TRANSACTION_bindService) {
        return;
    }

    offset = read_string16_from_user(parcel_base, info->data_size, offset,
                                     info->intent.action, sizeof(info->intent.action));
    offset = read_string16_from_user(parcel_base, info->data_size, offset,
                                     info->intent.uri, sizeof(info->intent.uri));
    offset = read_string16_from_user(parcel_base, info->data_size, offset,
                                     info->intent.package_name,
                                     sizeof(info->intent.package_name));
}

static __always_inline void capture_binder_objects(struct binder_txn_info *info,
                                                   const struct binder_transaction_data *txn)
{
    __u32 count = 0;
    __u32 i;

    if (txn->offsets_size == 0 || txn->data.ptr.offsets == 0) {
        return;
    }

    count = (__u32)min_u64(txn->offsets_size / sizeof(binder_size_t), MAX_BINDER_OBJECTS);
    info->n_objects = count;

    for (i = 0; i < MAX_BINDER_OBJECTS; i++) {
        binder_size_t obj_offset = 0;
        struct flat_binder_object obj = {};

        if (i >= count) {
            break;
        }

        if (bpf_probe_read_user(&obj_offset, sizeof(obj_offset),
                                (const void *)(untag_ptr(txn->data.ptr.offsets) +
                                               (i * sizeof(binder_size_t)))) != 0) {
            break;
        }

        if (obj_offset + sizeof(obj) > txn->data_size) {
            continue;
        }

        if (bpf_probe_read_user(&obj, sizeof(obj),
                                (const void *)(untag_ptr(txn->data.ptr.buffer) + obj_offset)) != 0) {
            continue;
        }

        info->objects[i].type = obj.hdr.type;
        info->objects[i].flags = obj.flags;
        info->objects[i].cookie = obj.cookie;
    }
}

SEC("tracepoint/raw_syscalls/sys_enter")
int binder_monitor(struct trace_event_raw_sys_enter_min *ctx)
{
    unsigned int cmd = 0;
    unsigned long arg = 0;
    __u32 zero = 0;
    __u64 current_cgroup_id = 0;
    __u64 *target_cgroup_id = 0;
    __u64 pid_tgid;
    __u64 uid_gid;
    struct binder_write_read bwr = {};
    struct binder_transaction_data txn = {};
    struct binder_txn_info *info;
    __u32 bcmd = 0;
    __u32 capture_size = 0;

    if (ctx->id != ARM64_NR_IOCTL) {
        return 0;
    }

    target_cgroup_id = bpf_map_lookup_elem(&target_cgroup_map, &zero);
    if (!target_cgroup_id || *target_cgroup_id == 0) {
        return 0;
    }

    current_cgroup_id = bpf_get_current_cgroup_id();
    bpf_printk("binder_monitor: ioctl cgroup cur=%llu target=%llu",
               current_cgroup_id, *target_cgroup_id);
    if (current_cgroup_id != *target_cgroup_id) {
        return 0;
    }

    cmd = (unsigned int)ctx->args[1];
    arg = (unsigned long)ctx->args[2];

    bpf_printk("binder_monitor: cgroup match! cmd=0x%x BINDER_WRITE_READ=0x%x",
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
    info->strict_mode = 0;
    info->work_source_uid = 0;
    info->interface[0] = '\0';
    info->payload_start = 0;
    info->intent.action[0] = '\0';
    info->intent.uri[0] = '\0';
    info->intent.package_name[0] = '\0';
    info->intent.component_pkg[0] = '\0';
    info->intent.component_class[0] = '\0';
    info->intent.flags = 0;
    info->n_objects = 0;
    info->parcel_captured = 0;

    if (bpf_probe_read_user(&bwr, sizeof(bwr), (const void *)arg) != 0) {
        return 0;
    }

    if (bwr.write_size < sizeof(bcmd) || bwr.write_buffer == 0) {
        return 0;
    }

    if (bpf_probe_read_user(&bcmd, sizeof(bcmd), (const void *)untag_ptr(bwr.write_buffer)) != 0) {
        return 0;
    }

    if (bcmd != (__u32)BC_TRANSACTION && bcmd != (__u32)BC_REPLY) {
        return 0;
    }

    if (bwr.write_size < sizeof(bcmd) + sizeof(txn)) {
        return 0;
    }

    if (bpf_probe_read_user(&txn, sizeof(txn),
                            (const void *)(untag_ptr(bwr.write_buffer) + sizeof(bcmd))) != 0) {
        return 0;
    }

    pid_tgid = bpf_get_current_pid_tgid();
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
            parse_parcel_header(info, buf_addr);
            parse_known_intent_fields(info, buf_addr);
        } else {
            info->parcel_captured = 0;
        }
    }

    txn.data.ptr.buffer = untag_ptr(txn.data.ptr.buffer);
    txn.data.ptr.offsets = untag_ptr(txn.data.ptr.offsets);
    capture_binder_objects(info, &txn);
    bpf_map_update_elem(&txn_map, &info->tid, info, BPF_ANY);
    bpf_printk("binder_monitor: recorded txn tid=%u bcmd=0x%x", info->tid, bcmd);
    return 0;
}
