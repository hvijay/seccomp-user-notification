#ifndef SECCOMP_BINDER_MONITOR_SHARED_TYPES_H_
#define SECCOMP_BINDER_MONITOR_SHARED_TYPES_H_

#include <linux/types.h>

#define PARCEL_CAPTURE_SIZE 1024
#define MAX_IFACE_LEN 128
#define MAX_ACTION_LEN 128
#define MAX_URI_LEN 256
#define MAX_PKG_LEN 128
#define MAX_CLASS_LEN 128
#define MAX_BINDER_OBJECTS 8

#define TRANSACTION_startActivity 1
#define TRANSACTION_sendBroadcast 14
#define TRANSACTION_startService 25
#define TRANSACTION_bindService 27

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
 */
#define PROXY_MSG_SET_TARGET  0x01
#define PROXY_MSG_LOOKUP_TID  0x02

struct parsed_intent {
    char action[MAX_ACTION_LEN];
    char uri[MAX_URI_LEN];
    char package_name[MAX_PKG_LEN];
    char component_pkg[MAX_PKG_LEN];
    char component_class[MAX_CLASS_LEN];
    __u32 flags;
};

struct binder_object_ref {
    __u32 type;
    __u64 cookie;
    __u32 flags;
};

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

    __u32 strict_mode;
    __u32 work_source_uid;
    char interface[MAX_IFACE_LEN];
    __u32 payload_start;

    struct parsed_intent intent;

    __u32 n_objects;
    __u32 parcel_captured;
    struct binder_object_ref objects[MAX_BINDER_OBJECTS];

    __u8 raw_parcel[PARCEL_CAPTURE_SIZE];
};

#endif  // SECCOMP_BINDER_MONITOR_SHARED_TYPES_H_
