#ifndef LOADER_COMPAT_BINDER_UAPI_MIN_H_
#define LOADER_COMPAT_BINDER_UAPI_MIN_H_

#include <linux/ioctl.h>
#include <linux/types.h>

typedef __u64 binder_size_t;
typedef __u64 binder_uintptr_t;

struct binder_write_read {
    binder_size_t    write_size;
    binder_size_t    write_consumed;
    binder_uintptr_t write_buffer;
    binder_size_t    read_size;
    binder_size_t    read_consumed;
    binder_uintptr_t read_buffer;
};

struct binder_transaction_data {
    union {
        __u32            handle;
        binder_uintptr_t ptr;
    } target;
    binder_uintptr_t cookie;
    __u32            code;
    __u32            flags;
    __s32            sender_pid;
    __u32            sender_euid;
    binder_size_t    data_size;
    binder_size_t    offsets_size;
    union {
        struct {
            binder_uintptr_t buffer;
            binder_uintptr_t offsets;
        } ptr;
        __u8 buf[8];
    } data;
};

#define BINDER_WRITE_READ  _IOWR('b', 1, struct binder_write_read)
#define BC_TRANSACTION     _IOW('c', 0, struct binder_transaction_data)
#define BC_REPLY           _IOW('c', 1, struct binder_transaction_data)

#endif  /* LOADER_COMPAT_BINDER_UAPI_MIN_H_ */
