#ifndef SECCOMP_BINDER_MONITOR_SHARED_TYPES_H_
#define SECCOMP_BINDER_MONITOR_SHARED_TYPES_H_

#include <linux/types.h>

#define PARCEL_CAPTURE_SIZE 1024
#define MAX_PATH_LEN 256

#define OP_KIND_UNKNOWN 0
#define OP_KIND_BINDER 1
#define OP_KIND_FILE_OPEN 2
#define OP_KIND_EXEC 3

#define MAX_ARGV_SUMMARY_LEN 512
/*
 * Proxy socket protocol (policydaemon -> loader daemon).
 *
 * Each request starts with a uint8_t message type:
 *
 *   PROXY_MSG_SET_TARGET  0x01
 *     payload:  uint32_t pid  (0 = disable monitoring)
 *     response: uint8_t ok   (1 = success, 0 = error)
 *
 *   PROXY_MSG_LOOKUP_TID  0x02
 *     payload:  uint32_t tid
 *     response: uint8_t found + struct binder_txn_info info
 *
 *   PROXY_MSG_REGISTER_LISTENER  0x03
 *     payload:  ancillary fd (seccomp listener)
 *     response: uint8_t ok
 *
 *   PROXY_MSG_GET_PENDING  0x04
 *     payload:  none
 *     response: uint8_t found + struct proxy_pending_request request
 *
 *   PROXY_MSG_SEND_DECISION  0x05
 *     payload:  uint64_t notification_id + int32_t allow
 *     response: uint8_t ok
 *
 *   PROXY_MSG_UNREGISTER  0x06
 *     payload:  none
 *     response: uint8_t ok
 */
#define PROXY_MSG_SET_TARGET  0x01
#define PROXY_MSG_LOOKUP_TID  0x02
#define PROXY_MSG_REGISTER_LISTENER  0x03
#define PROXY_MSG_GET_PENDING  0x04
#define PROXY_MSG_SEND_DECISION  0x05
#define PROXY_MSG_UNREGISTER  0x06

struct binder_txn_info {
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u64 timestamp_ns;

    __u32 target_handle;
    __u32 code;
    __u32 flags;
    __u32 data_size;
    __u32 offsets_size;
    __u8 is_reply;
    __u8 parcel_truncated;
    __u32 parcel_captured;
    __u8 raw_parcel[PARCEL_CAPTURE_SIZE];
};

struct proxy_pending_request {
    __u64 notification_id;
    __u32 pid;
    __u32 syscall_nr;
    __u32 operation_kind;
    __u64 ioctl_cmd;
    __u32 open_flags;
    __u32 open_mode;
    char file_path[MAX_PATH_LEN];
    char exec_argv[MAX_ARGV_SUMMARY_LEN];
    struct binder_txn_info txn;
};

#endif  // SECCOMP_BINDER_MONITOR_SHARED_TYPES_H_
