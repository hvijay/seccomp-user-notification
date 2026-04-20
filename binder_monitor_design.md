# Binder Monitor: Design Document and Implementation Plan

**Project:** Single-Process Binder IPC Monitor  
**Architecture:** cgroup-scoped eBPF + seccomp-unotify  
**Constraint:** No `process_vm_readv` — all data capture via eBPF kernel context  
**Date:** 2026-04-20  

---

## Table of Contents

1. [Goals and Constraints](#1-goals-and-constraints)
2. [System Architecture](#2-system-architecture)
3. [Component Design](#3-component-design)
   - 3.1 [Shared Types](#31-shared-types)
   - 3.2 [eBPF Program](#32-ebpf-program)
   - 3.3 [Cgroup Management](#33-cgroup-management)
   - 3.4 [eBPF Loader](#34-ebpf-loader)
   - 3.5 [seccomp Filter and unotify Injection](#35-seccomp-filter-and-unotify-injection)
   - 3.6 [Supervisor](#36-supervisor)
   - 3.7 [Policy Engine](#37-policy-engine)
   - 3.8 [Daemon Lifecycle](#38-daemon-lifecycle)
4. [Data Flow](#4-data-flow)
5. [Correctness Invariants](#5-correctness-invariants)
6. [Performance Budget](#6-performance-budget)
7. [Implementation Plan](#7-implementation-plan)
8. [Repository Structure](#8-repository-structure)
9. [Build System](#9-build-system)
10. [Testing Strategy](#10-testing-strategy)
11. [Known Limitations and Future Work](#11-known-limitations-and-future-work)

---

## 1. Goals and Constraints

### Goals

- Monitor all outbound Binder IPC from a single target Android process.
- Decode transaction identity (handle, code, flags, interface descriptor) and common payload types (Intent, ContentProvider URIs) with no cooperation from the target process.
- Support allow/deny decisions on each transaction before it reaches the Binder driver.
- Zero overhead on all processes other than the monitored target.

### Hard Constraints

| Constraint | Implication |
|---|---|
| Cannot modify SELinux policy for `untrusted_app` | Cannot use `ptrace`, `process_vm_readv`, or `/proc/<pid>/mem` on the target |
| Can modify the kernel (but minimally) | eBPF tracepoints and cgroup attachment are available |
| Can install a privileged daemon via `init` | Daemon has its own SELinux domain with rules scoped to itself only |
| Cannot modify SELinux policy for any existing domain | All new policy rules apply only to the new daemon domain |

### What "No `process_vm_readv`" Means for the Design

All Parcel data the daemon will ever see must be captured by the eBPF program executing in kernel context, where no LSM permission check applies to memory reads. The daemon receives fully parsed, structured data — it never interprets raw bytes from the target process's address space.

---

## 2. System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Target App Process  (uid=10187, cgroup=/sys/fs/cgroup/uid_10187/...)   │
│                                                                         │
│  Java: transact() → IPCThreadState::transact() → ioctl(BINDER_WRITE_READ)
│                                                         │               │
└─────────────────────────────────────────────────────────┼───────────────┘
                                                          │
                           ┌──────────────────────────────┼───────────────┐
                           │  Kernel                       │               │
                           │                               ▼               │
                           │  raw_syscalls/sys_enter ──► eBPF program      │
                           │  (cgroup-scoped: only fires  │                │
                           │   for target process)        │ bpf_probe_read_user
                           │                              │ (no LSM check) │
                           │                              ▼               │
                           │                         txn_map (HASH)       │
                           │                         key: tid             │
                           │                         value: binder_txn_info
                           │                              │               │
                           │  seccomp filter ──────────── │ ──────────────│
                           │  (BINDER_WRITE_READ only)    │               │
                           │  → SECCOMP_RET_USER_NOTIF    │               │
                           │                              │               │
                           └──────────────────────────────┼───────────────┘
                                                          │
                    ┌─────────────────────────────────────▼───────────────┐
                    │  Supervisor Daemon  (u:r:binder_monitor_d:s0)       │
                    │                                                     │
                    │  epoll_wait(notifyfd)                               │
                    │    → SECCOMP_IOCTL_NOTIF_RECV                       │
                    │    → bpf_map_lookup_and_delete(txn_map, tid)        │
                    │    → policy_evaluate(binder_txn_info)               │
                    │    → SECCOMP_IOCTL_NOTIF_SEND (ALLOW / DENY)        │
                    │                                                     │
                    └─────────────────────────────────────────────────────┘
```

### Key Architectural Properties

**Ordering guarantee:** `raw_syscalls/sys_enter` fires before `__secure_computing()` in the kernel's `syscall_enter_from_user_mode()`. The eBPF program always writes to `txn_map` before seccomp wakes the daemon. No locking is required between the eBPF write and the daemon read because the app thread is frozen from the moment the unotify fires until the daemon sends its response.

**Scope guarantee:** The eBPF program is attached to the target's cgroup, not the global `raw_syscalls/sys_enter` tracepoint. It is never invoked for any thread outside that cgroup.

**Data completeness:** Because the eBPF program runs in kernel context, `bpf_probe_read_user` requires no capability or SELinux check. All Parcel bytes, Binder object offsets, and kernel-verified credentials are captured before the daemon is woken.

---

## 3. Component Design

### 3.1 Shared Types

**File:** `common/shared_types.h`  
**Included by:** eBPF program (via vmlinux.h path) and daemon userspace code.

This file is the contract between the kernel and userspace halves of the system. Any change here requires recompiling both.

#### Size Constants

```c
#define PARCEL_CAPTURE_SIZE   1024   // max Parcel bytes captured per transaction
#define MAX_IFACE_LEN         128    // interface descriptor string
#define MAX_ACTION_LEN        128    // Intent action string
#define MAX_URI_LEN           256    // Intent data URI string
#define MAX_PKG_LEN           128    // package / component package name
#define MAX_CLASS_LEN         128    // component class name
#define MAX_BINDER_OBJECTS    8      // flat_binder_object entries per transaction
```

#### Known AMS Transaction Codes

```c
// IActivityManager transaction codes (FIRST_CALL_TRANSACTION = 1)
#define TRANSACTION_startActivity    1
#define TRANSACTION_startService     25
#define TRANSACTION_sendBroadcast    14
#define TRANSACTION_bindService      27
```

These are derived from the AOSP AIDL-generated `IActivityManager` stubs. They must be verified against the target Android version at integration time.

#### Core Structs

```c
struct parsed_intent {
    char     action[MAX_ACTION_LEN];
    char     uri[MAX_URI_LEN];
    char     package[MAX_PKG_LEN];
    char     component_pkg[MAX_PKG_LEN];
    char     component_class[MAX_CLASS_LEN];
    uint32_t flags;
};

struct binder_object_ref {
    uint32_t type;    // BINDER_TYPE_BINDER, BINDER_TYPE_HANDLE, BINDER_TYPE_FD, ...
    uint64_t cookie;
    uint32_t flags;
};

struct binder_txn_info {
    // Kernel-verified identity (from task_struct, not from userspace)
    uint32_t pid;
    uint32_t tid;
    uint32_t uid;
    uint64_t timestamp_ns;

    // Binder transaction header
    uint32_t target_handle;
    uint32_t code;
    uint32_t flags;
    uint32_t data_size;
    uint32_t offsets_size;
    uint8_t  is_reply;
    uint8_t  parcel_truncated;  // set if data_size > PARCEL_CAPTURE_SIZE

    // Parcel header fields (parsed in eBPF)
    uint32_t strict_mode;
    uint32_t work_source_uid;
    char     interface[MAX_IFACE_LEN];
    uint32_t payload_start;  // byte offset where AIDL args begin

    // Structured fields for known transaction types (parsed in eBPF)
    struct parsed_intent intent;

    // Binder object table
    uint32_t n_objects;
    uint32_t parcel_captured;  // actual bytes written to raw_parcel
    struct binder_object_ref objects[MAX_BINDER_OBJECTS];

    // Raw Parcel bytes — used by daemon only for unrecognised transaction codes
    uint8_t  raw_parcel[PARCEL_CAPTURE_SIZE];
};
```

**Total size of `binder_txn_info`:** approximately 2.1 KB. This exceeds the BPF stack limit (512 bytes) and must live in a per-CPU map, not on the BPF stack.

---

### 3.2 eBPF Program

**File:** `kernel/binder_monitor.bpf.c`  
**Attach type:** `tracepoint/raw_syscalls/sys_enter`, scoped to target cgroup  
**Build output:** `kernel/binder_monitor.bpf.o`, skeleton at `kernel/binder_monitor.skel.h`

#### Maps

| Map | Type | Entries | Key | Value | Purpose |
|---|---|---|---|---|---|
| `scratch` | `PERCPU_ARRAY` | 1 | `u32 zero` | `binder_txn_info` | BPF stack overflow buffer |
| `txn_map` | `HASH` | 64 | `u32 tid` | `binder_txn_info` | Hand-off to daemon |

`txn_map` is pinned at `/sys/fs/bpf/binder_monitor/txn_map`. The daemon opens it by path at startup using `bpf_obj_get()`.

`scratch` uses per-CPU storage. The eBPF program writes into `scratch[0]` on the current CPU, then copies it into `txn_map`. Because the app thread is pinned to one CPU during the eBPF execution window, and the unotify freeze prevents the thread from re-entering until the daemon responds, there is no aliasing between CPUs for the same tid.

#### Execution Path

```
sys_enter fires
  │
  ├─ nr != __NR_ioctl?          → return 0   (free)
  ├─ args[1] != BINDER_WRITE_READ? → return 0 (free)
  │
  ├─ lookup scratch[0] (per-CPU)
  ├─ __builtin_memset(scratch, 0)
  │
  ├─ bpf_probe_read_user: binder_write_read from args[2]
  ├─ check write_size ≥ minimum              → return 0 on fail
  │
  ├─ bpf_probe_read_user: bcmd from write_buffer
  ├─ bcmd != BC_TRANSACTION && != BC_REPLY   → return 0
  │
  ├─ bpf_probe_read_user: binder_transaction_data
  │
  ├─ populate metadata fields from bpf_get_current_pid_tgid / uid_gid / ktime
  │
  ├─ capture flat_binder_objects (bounded loop, max MAX_BINDER_OBJECTS)
  │    └─ bpf_probe_read_user: offsets table entry
  │    └─ bpf_probe_read_user: flat_binder_object at offset
  │
  ├─ bpf_probe_read_user: Parcel bytes (capped at PARCEL_CAPTURE_SIZE)
  │
  ├─ parse_parcel_header(): strict_mode, work_source_uid, interface, payload_start
  │
  ├─ if code ∈ {startActivity, startService, sendBroadcast, bindService}:
  │    └─ parse_intent(): action, uri, package, component
  │
  └─ bpf_map_update_elem(txn_map, &tid, scratch, BPF_ANY)
```

#### Internal Helpers

**`read_string16(uptr, out, max_chars)`**  
Reads a UTF-16LE string from userspace into a fixed-size ASCII buffer. Uses a single `bpf_probe_read_user` call for all code units, then copies low bytes. Returns character count. Bounded loop with compile-time visible limit — required by the BPF verifier.

**`skip_string16(parcel, pos, limit)`**  
Advances `pos` past a string16 field (length word + UTF-16 data + padding to 4-byte alignment) without reading the string data. Used to skip fields the eBPF program doesn't need to decode.

**`parse_parcel_header(buf, data_size, info)`**  
Reads the standard AIDL Parcel preamble: strict mode policy (4 bytes), work source UID (4 bytes), interface descriptor string16. Sets `info->payload_start` to the byte offset where AIDL arguments begin.

**`parse_intent(buf, pos, limit, intent)`**  
Parses Android Intent wire format starting at `pos`: action, URI (with type discrimination), MIME type (skipped), flags, package, component. Writes into `info->intent`. All string reads are bounded.

#### BPF Verifier Compliance

- All loops use `for (int i = 0; i < COMPILE_TIME_CONST; i++)` form.
- All pointer arithmetic is bounds-checked before `bpf_probe_read_user`.
- No unbounded memory accesses.
- Stack usage stays under 512 bytes by using `scratch` map for the large struct.
- `__builtin_memset` is used (not `__memset`) so the verifier recognizes it as a bulk zero.

---

### 3.3 Cgroup Management

**File:** `daemon/cgroup.c`

#### `cgroup_find(pid_t pid) → char*`

Reads `/proc/<pid>/cgroup`, parses the line beginning with `0::`, prepends `/sys/fs/cgroup`, verifies the path exists, and returns a heap-allocated string. The caller frees it.

Android places app processes at `/sys/fs/cgroup/uid_<uid>/pid_<tgid>/`. Parse from `/proc` rather than constructing this path — more robust across Android versions and avoids uid-lookup races.

#### `cgroup_open_fd(const char *path) → int`

Opens the cgroup directory with `O_RDONLY | O_DIRECTORY`. Returns the fd used in `bpf_prog_attach`. The caller closes it after detaching the eBPF program.

#### `cgroup_watch(pid_t pid, void (*cb)(void*), void *arg) → int`

Sets up an `inotify` watch on `/proc/<pid>` for `IN_DELETE_SELF`. When the watch fires, the target process has exited. Calls `cb(arg)` to trigger daemon shutdown. Returns an fd suitable for adding to the supervisor's epoll set.

---

### 3.4 eBPF Loader

**File:** `daemon/ebpf_loader.c`

Owns the full lifecycle of the eBPF program and its maps.

#### `ebpf_loader_init(pid_t target_pid) → ebpf_handle*`

```
1. binder_monitor_bpf__open()        — parse ELF, don't load yet
2. binder_monitor_bpf__load()        — load into kernel, verifier runs
3. mkdir /sys/fs/bpf/binder_monitor  — create pin directory if absent
4. bpf_map__pin(txn_map, path)       — pin map so daemon can open by path
5. cgroup_find(target_pid)           — get cgroup path string
6. cgroup_open_fd(cgroup_path)       — open cgroup dir fd
7. bpf_prog_attach(prog_fd,          — scope program to target cgroup only
                   cgroup_fd,
                   BPF_CGROUP_INET_SOCK_CREATE, 0)
   NOTE: for syscall tracing, use the tracepoint attachment path:
         bpf_program__attach_tracepoint scoped via cgroup_fd
8. Store skeleton, cgroup_fd, map_fd in handle
9. Return handle
```

Any failure triggers cleanup of all resources initialized so far. Partial state is never returned.

#### `ebpf_loader_get_map_fd(handle) → int`

Returns the `txn_map` fd for the supervisor to use in `bpf_map_lookup_and_delete_elem` calls.

#### `ebpf_loader_teardown(handle)`

```
1. bpf_prog_detach from cgroup
2. bpf_map__unpin(txn_map)  — unlink /sys/fs/bpf/binder_monitor/txn_map
3. close(cgroup_fd)
4. binder_monitor_bpf__destroy(skeleton)
5. free(handle)
```

Teardown order matters: detach program before destroying skeleton, so no eBPF code runs against maps that are being freed.

---

### 3.5 seccomp Filter and unotify Injection

**File:** `daemon/zygote_hook.c`

#### Filter Design

The seccomp BPF filter installed in the target process must be as narrow as possible. It generates a `SECCOMP_RET_USER_NOTIF` only for `ioctl(BINDER_WRITE_READ)`. All other syscalls — including all other ioctls — pass through with `SECCOMP_RET_ALLOW` at near-zero cost.

```
Filter logic:
  load nr
  if nr != __NR_ioctl:               ALLOW   (~2 ns, taken by ~99% of syscalls)
  load args[1] low 32 bits
  if != (BINDER_WRITE_READ & 0xFFFF): ALLOW  (~2 ns, taken by most ioctls)
  load args[1] high 32 bits
  if != (BINDER_WRITE_READ >> 32):    ALLOW
                                      USER_NOTIF
```

#### Injection Strategy — Zygote Plugin (preferred)

Install the filter from within the child process during `postForkChild()` in the Zygote hook (see earlier discussion of Zygisk-style injection). This avoids ptrace entirely.

```
In the child process, before DropCapabilities():
  1. Build sock_fprog for the BINDER_WRITE_READ filter
  2. notifyfd = syscall(SYS_seccomp,
                        SECCOMP_SET_MODE_FILTER,
                        SECCOMP_FILTER_FLAG_NEW_LISTENER,
                        &prog)
  3. Send notifyfd to daemon via pre-opened Unix socket using SCM_RIGHTS
  4. close(notifyfd) in child — daemon holds the only copy
```

The daemon receives the `notifyfd` before the target process has executed any app code. This is the earliest possible injection point.

#### Injection Strategy — ptrace fallback

If Zygote modification is not available, attach via `ptrace(PTRACE_SEIZE)` and inject a small shellcode stub that installs the filter and returns the notifyfd over a socket. This strategy has a narrow race window between process start and ptrace attachment; prefer the Zygote strategy where possible.

---

### 3.6 Supervisor

**File:** `daemon/supervisor.c`

Single-threaded event loop. The app thread is frozen for the entire duration of each `handle_notification` call, so no concurrent access to shared state is possible.

#### Initialization

```c
supervisor_init(notifyfd, map_fd, target_pid, exit_eventfd) → supervisor*
```

- Allocates `seccomp_notif` and `seccomp_notif_resp` buffers using sizes returned by `SECCOMP_IOCTL_NOTIF_SIZES` — do not hardcode these; they vary by kernel version.
- Creates `epollfd`.
- Adds `notifyfd` (EPOLLIN) and `exit_eventfd` (EPOLLIN) to epoll set.

#### Main Loop

```c
supervisor_run(supervisor*):
  while not shutdown:
    n = epoll_wait(epollfd, &event, 1, timeout=-1)
    if event.fd == notifyfd:  handle_notification(s)
    if event.fd == exit_eventfd: break
```

`epoll_wait` with `timeout=-1` consumes zero CPU when the target process is idle.

#### `handle_notification`

```
1. SECCOMP_IOCTL_NOTIF_RECV(req)
     on EINTR: retry
     on other error: return

2. SECCOMP_IOCTL_NOTIF_ID_VALID(req->id)
     on fail (ENOENT): thread died between notify and recv — return without send

3. tid = req->pid  (Linux reports tid here for multithreaded processes)

4. bpf_map_lookup_and_delete_elem(map_fd, &tid, &info)
     on fail: log anomaly, allow the call, goto send

5. policy_evaluate(&info) → Decision

6. switch Decision:
     ALLOW: resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE
     DENY:  resp.error = -EPERM; resp.flags = 0

7. log_transaction(&info, Decision)

8. SECCOMP_IOCTL_NOTIF_SEND(resp)
     on ENOENT: thread died, discard (normal)
     on other error: log
```

`bpf_map_lookup_and_delete_elem` is used rather than a separate lookup + delete. This atomically retrieves and removes the entry, preventing stale entries from accumulating if the supervisor is slow.

---

### 3.7 Policy Engine

**File:** `daemon/policy.c`

Operates entirely on `binder_txn_info` structs. Never reads from the target process's address space.

#### Rule Table

```c
typedef Decision (*evaluate_fn)(const struct binder_txn_info *);

typedef struct {
    uint32_t    target_handle;  // 0 = wildcard
    uint32_t    code;           // 0 = wildcard
    evaluate_fn fn;
} PolicyRule;
```

Rules are evaluated in order; first match wins. The default terminal rule returns `DECISION_ALLOW`.

#### Built-in Rule Examples

```
handle=any, code=startActivity    → check intent.uri scheme
handle=any, code=sendBroadcast    → check intent.action allowlist
handle=any, n_objects > 0,
  any object type == BINDER_TYPE_FD → check target_handle trustworthiness
handle=any, code=any              → ALLOW  (default)
```

#### Decision Values

| Value | Supervisor Action |
|---|---|
| `DECISION_ALLOW` | `SECCOMP_USER_NOTIF_FLAG_CONTINUE` — ioctl proceeds normally |
| `DECISION_DENY` | `resp.error = -EPERM` — ioctl returns error to app |

`DECISION_MODIFY` (modify Parcel bytes in-flight) is explicitly out of scope for this version — it requires writing to the target's address space, which is unavailable without `process_vm_readv`. It is listed here as a future capability.

---

### 3.8 Daemon Lifecycle

**File:** `daemon/main.c`

```
main(argc, argv):
  1. Parse --pid <n> or --package <name>
     If --package: scan /proc for matching cmdline, or
                   wait for Zygote fork notification

  2. Validate target: kill(pid, 0) == 0

  3. ebpf_loader_init(target_pid)
       on fail: log + exit(1)

  4. Receive notifyfd from Zygote plugin over Unix socket
     (socket path established at daemon start, before target launches)

  5. exit_eventfd = eventfd(0, EFD_CLOEXEC)

  6. cgroup_watch(target_pid, on_target_exit, &exit_eventfd)

  7. supervisor_init(notifyfd, map_fd, target_pid, exit_eventfd)

  8. Signal handlers: SIGTERM/SIGINT → write(exit_eventfd, 1)

  9. supervisor_run()  [blocks]

  10. Cleanup (also registered via atexit):
        ebpf_loader_teardown()
        close(notifyfd)
        close(exit_eventfd)
        exit(0)
```

---

## 4. Data Flow

```
Timeline for a single Binder transaction:

 App Thread (tid=T)          Kernel                    Daemon
 ──────────────────          ──────────────────────    ──────────────────
 transact()
   │
   ▼
 ioctl(fd,                ── enters kernel ──►
 BINDER_WRITE_READ,bwr)      │
                             ▼
                         sys_enter tracepoint
                         eBPF program runs:
                           probe_read bwr
                           probe_read txn_data
                           probe_read parcel bytes
                           parse header + intent
                           write txn_map[T] = info
                             │
                             ▼
                         __secure_computing()
                         seccomp filter matches:
                         BINDER_WRITE_READ
                           → SECCOMP_RET_USER_NOTIF
                         app thread FROZEN ──────────► epoll_wait returns
                                                        NOTIF_RECV → req
                                                        NOTIF_ID_VALID ✓
                                                        map_lookup_and_delete(T)
                                                          → info (fully parsed)
                                                        policy_evaluate(info)
                                                          → ALLOW / DENY
                                                        NOTIF_SEND(resp)
                             │                              │
                             ◄──────────────────────────────┘
                         app thread UNFROZEN
                         binder_transaction() runs
                         (or returns -EPERM to app)
```

---

## 5. Correctness Invariants

These must hold at all times. Debug builds should assert them.

### I1: Map Entry Lifetime

Every entry written to `txn_map` by the eBPF program must be consumed (via `bpf_map_lookup_and_delete_elem`) by the daemon within the same unotify handling cycle. An entry must not survive past its corresponding `SECCOMP_IOCTL_NOTIF_SEND`.

**Failure mode:** Map fills to `max_entries=64`. Subsequent eBPF `bpf_map_update_elem` calls with `BPF_NOEXIST` silently fail. Transactions are allowed through without logging or policy evaluation.

**Mitigation:** Use `BPF_ANY` in `bpf_map_update_elem` so stale entries from crashed threads are overwritten rather than blocking. Monitor map utilization via `bpftool map` in tests.

### I2: Notification Liveness

Always call `SECCOMP_IOCTL_NOTIF_ID_VALID` between `RECV` and any `SEND`. A thread can be killed between the kernel generating the notification and the daemon processing it. `ENOENT` on `NOTIF_ID_VALID` is a normal condition, not an error.

### I3: Frozen Thread Guarantee

The app thread is frozen from `SECCOMP_RET_USER_NOTIF` until `SECCOMP_IOCTL_NOTIF_SEND`. The daemon must not block during `handle_notification` on anything that requires the app thread to be running (e.g., waiting for a Binder reply from the target process).

### I4: Single Consumer

Exactly one thread must call `SECCOMP_IOCTL_NOTIF_RECV` on a given `notifyfd`. Multiple consumers result in lost notifications and undefined behaviour. The supervisor is single-threaded by design.

### I5: Teardown Order

```
Correct order:
  1. Stop supervisor loop
  2. bpf_prog_detach from cgroup     ← no more eBPF writes after this
  3. close(notifyfd)                 ← no more notifications after this
  4. Flush / drain remaining map entries
  5. bpf_map__unpin + destroy skeleton

Wrong order (use-after-free risk):
  destroy skeleton → then detach prog
  (prog still runs against freed map)
```

### I6: Verifier Bounds

All loops in the eBPF program must have a compile-time-visible bound. All pointer arithmetic into Parcel data must be preceded by an explicit bounds check. A verifier rejection is a build failure, not a runtime failure.

---

## 6. Performance Budget

| Metric | Target | Measurement Method |
|---|---|---|
| Added latency per Binder call | < 50 µs | `bpftrace` latency histogram on target |
| CPU overhead when target is idle | 0% | `perf stat` on unrelated processes |
| CPU overhead during active Binder calls | < 1% of one core | `perf top` during monkey runner |
| BPF map peak utilization | < 50% (< 32 entries) | `bpftool map dump` during stress test |
| Daemon RSS | < 4 MB | `/proc/<daemon_pid>/status` |
| eBPF program instruction count | < 4096 (verifier limit) | `bpftool prog show` |

---

## 7. Implementation Plan

### Phase 0: Prerequisites (Day 1)

- [ ] Confirm kernel version supports: `BPF_MAP_TYPE_PERCPU_ARRAY`, `bpf_map_lookup_and_delete_elem`, `SECCOMP_FILTER_FLAG_NEW_LISTENER`, `SECCOMP_IOCTL_NOTIF_ID_VALID`, cgroup-scoped eBPF attachment.
- [ ] Confirm `BINDER_WRITE_READ` ioctl number for target architecture (arm64 vs x86_64).
- [ ] Confirm AMS transaction codes against target Android version's AIDL-generated stubs.
- [ ] Set up build environment: clang with BPF target, bpftool, libbpf.
- [ ] Obtain vmlinux.h for target kernel: `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`

### Phase 1: Shared Types and eBPF Skeleton (Days 2–4)

- [ ] Author `common/shared_types.h` with all structs and constants.
- [ ] Write minimal eBPF program: metadata only, no Parcel parsing.
- [ ] Compile: `clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 -c binder_monitor.bpf.c -o binder_monitor.bpf.o`
- [ ] Verify with `bpftool prog load binder_monitor.bpf.o /sys/fs/bpf/test` — verifier must accept.
- [ ] Generate skeleton: `bpftool gen skeleton binder_monitor.bpf.o > binder_monitor.skel.h`

**Milestone:** `bpftool prog load` succeeds with zero verifier errors. `bpftool map dump` shows empty `txn_map`.

### Phase 2: Cgroup Attachment and Map Population (Days 5–7)

- [ ] Implement `cgroup.c`: `cgroup_find`, `cgroup_open_fd`.
- [ ] Implement `ebpf_loader.c`: load skeleton, pin map, attach to cgroup.
- [ ] Write a test harness that launches a known process, attaches the eBPF program, and dumps `txn_map` entries.

**Milestone:** After the test process makes a Binder call, `bpftool map dump pinned /sys/fs/bpf/binder_monitor/txn_map` shows a populated `binder_txn_info` entry with correct `tid`, `code`, and `target_handle`. No entries appear for any other process.

### Phase 3: seccomp Filter and unotify (Days 8–10)

- [ ] Implement the seccomp BPF filter in `zygote_hook.c`.
- [ ] Implement the Zygote-plugin injection path (Strategy B): install filter in child, send notifyfd over Unix socket.
- [ ] Implement `supervisor.c` in allow-all mode: recv notification, log it, always send CONTINUE.

**Milestone:** Every Binder call from the target process logs a line to the daemon. The target process functions normally (all calls allowed). No Binder calls from other processes are logged.

### Phase 4: Map Correlation (Days 11–12)

- [ ] Wire `handle_notification` to perform `bpf_map_lookup_and_delete_elem` keyed by `req->pid` (tid).
- [ ] Log the structured `binder_txn_info` fields: interface descriptor, code, intent fields.
- [ ] Verify `parcel_truncated` is never set for typical transactions (data_size < 1024).

**Milestone:** A `startActivity(Intent("android.intent.action.VIEW", Uri.parse("https://example.com")))` call from the target produces a log entry containing the action string and URI, with no `process_vm_readv` call anywhere in the daemon.

### Phase 5: Parcel Parsing in eBPF (Days 13–16)

- [ ] Implement `parse_parcel_header` helper in eBPF program.
- [ ] Implement `read_string16` and `skip_string16` helpers.
- [ ] Implement `parse_intent` for `startActivity` / `sendBroadcast` transaction codes.
- [ ] Add bounded loop for `flat_binder_object` capture.
- [ ] Re-verify with `bpftool prog load` after each addition — catch verifier issues early.

**Milestone:** `info.intent.action`, `info.intent.uri`, and `info.interface` are populated correctly for all tested transaction types. BPF instruction count remains under 4096.

### Phase 6: Policy Engine (Days 17–19)

- [ ] Implement `policy.c` with rule table and `policy_evaluate`.
- [ ] Add built-in rules: URI scheme check, action allowlist, FD-passing detection.
- [ ] Wire policy decisions into `handle_notification`: DENY returns `-EPERM` to app.
- [ ] Test: a `startActivity` with an `http://` URI is denied; the app receives `SecurityException` (wrapping the EPERM).

**Milestone:** End-to-end allow/deny working. Denied calls return a clean error to the app without crashing the target process or the daemon.

### Phase 7: Lifecycle and Hardening (Days 20–23)

- [ ] Implement `cgroup_watch` with inotify for target process exit detection.
- [ ] Implement graceful shutdown: SIGTERM → eventfd write → epoll wakes → teardown.
- [ ] Handle all `ENOENT` paths in notification handling (thread death races).
- [ ] Implement correct teardown order per Invariant I5.
- [ ] Add `SECCOMP_IOCTL_NOTIF_ID_VALID` check per Invariant I2.
- [ ] Stress test with Android Monkey runner (10,000 events). Verify no hangs, no map exhaustion, no daemon crashes.

**Milestone:** Monkey runner completes 10,000 events against the target with no daemon crash, no target ANR attributable to the monitor, and map utilization never exceeds 50%.

### Phase 8: Performance Validation (Days 24–25)

- [ ] Measure per-call latency overhead with `bpftrace`.
- [ ] Measure CPU overhead on unrelated processes with `perf stat`.
- [ ] Verify daemon RSS stays under 4 MB.
- [ ] Profile eBPF instruction count and hot paths.
- [ ] Tune `PARCEL_CAPTURE_SIZE` and `max_entries` based on measurements.

**Milestone:** All metrics in the Performance Budget table are met.

---

## 8. Repository Structure

```
binder_monitor/
│
├── common/
│   └── shared_types.h              # Contract between eBPF and daemon
│                                   # Symlinked into kernel/ and daemon/
│
├── kernel/
│   ├── vmlinux.h                   # Generated from target kernel BTF
│   ├── binder_monitor.bpf.c        # eBPF program
│   └── binder_monitor.skel.h       # Generated by bpftool gen skeleton
│
├── daemon/
│   ├── main.c                      # Entry point, lifecycle
│   ├── supervisor.c / supervisor.h # seccomp-unotify event loop
│   ├── ebpf_loader.c / ebpf_loader.h  # BPF load + cgroup attach
│   ├── cgroup.c / cgroup.h         # Cgroup discovery + inotify watch
│   ├── zygote_hook.c / zygote_hook.h  # seccomp filter injection
│   └── policy.c / policy.h         # Allow/deny rule engine
│
├── tests/
│   ├── test_parcel_parse.c          # Unit tests for eBPF parse helpers
│   │                                # (compiled for host, not BPF target)
│   ├── test_policy.c                # Unit tests for policy rule evaluation
│   └── monkey_stress.sh             # Monkey runner stress test script
│
└── Android.bp                       # Android build system rules
```

---

## 9. Build System

### eBPF Program

```makefile
# Compile eBPF program
clang -O2 -g                          \
      -target bpf                     \
      -D__TARGET_ARCH_arm64           \
      -I./kernel                      \
      -I./common                      \
      -c kernel/binder_monitor.bpf.c  \
      -o kernel/binder_monitor.bpf.o

# Generate BTF-enabled skeleton header
bpftool gen skeleton kernel/binder_monitor.bpf.o \
        > kernel/binder_monitor.skel.h
```

### Daemon

```makefile
CFLAGS  = -O2 -Wall -Wextra -I./common -I./kernel
LDFLAGS = -lbpf -lelf -lz

SRCS = daemon/main.c        \
       daemon/supervisor.c  \
       daemon/ebpf_loader.c \
       daemon/cgroup.c      \
       daemon/zygote_hook.c \
       daemon/policy.c

binder_monitor_daemon: $(SRCS) kernel/binder_monitor.skel.h
	$(CC) $(CFLAGS) $(SRCS) $(LDFLAGS) -o $@
```

### Android.bp (for AOSP integration)

```
cc_binary {
    name: "binder_monitor_daemon",
    srcs: ["daemon/*.c"],
    shared_libs: ["libbpf", "liblog"],
    include_dirs: ["common", "kernel"],
    init_rc: ["binder_monitor.rc"],
}
```

---

## 10. Testing Strategy

### Unit Tests

| Test | What it validates |
|---|---|
| `test_parcel_parse` | Parse helpers against hand-crafted Parcel byte arrays for all supported transaction types |
| `test_policy` | Each policy rule against synthetic `binder_txn_info` structs |
| `test_cgroup_find` | cgroup path parsing for multiple Android versions' `/proc/<pid>/cgroup` formats |

### Integration Tests

| Test | What it validates |
|---|---|
| `startActivity` allow | Intent action + URI logged; call succeeds |
| `startActivity` deny | `-EPERM` returned to app; target does not crash |
| `sendBroadcast` | Action string captured; policy applied |
| FD passing detection | `n_objects > 0` with `BINDER_TYPE_FD` detected |
| Large Parcel | `parcel_truncated` set when `data_size > PARCEL_CAPTURE_SIZE`; header still parsed |
| Thread death race | Target thread killed mid-transaction; daemon handles `ENOENT` cleanly |
| Map exhaustion | 65 concurrent threads all calling Binder; 64th does not hang daemon |
| Target exit | Target process exits; daemon shuts down cleanly via cgroup inotify |
| Unrelated process isolation | Heavy Binder activity in unrelated process; zero daemon CPU usage |

### Stress Test

```bash
# tests/monkey_stress.sh
adb shell monkey -p com.target.app \
    --throttle 10 \
    --ignore-crashes \
    --ignore-timeouts \
    -v 10000

# Pass criteria:
#   - Daemon still running at end
#   - bpftool map dump shows 0 entries (all consumed)
#   - No ANR dialogs on target
#   - perf stat shows 0% sys CPU on unrelated processes
```

---

## 11. Known Limitations and Future Work

### Parcel Truncation

Transactions with `data_size > PARCEL_CAPTURE_SIZE` (1024 bytes) will have `parcel_truncated = 1`. The header and intent fields are still parsed if they fall within the captured region. Large transactions (e.g., bulk ContentProvider reads, large Bundle extras) may not be fully decoded.

**Mitigation:** Increase `PARCEL_CAPTURE_SIZE` if BPF instruction budget allows. Alternatively, implement a two-pass approach: allow the transaction, capture the reply in a separate `sys_exit` tracepoint attachment.

### Transaction Code Coverage

Only four AMS transaction codes are parsed for Intent fields. All other transaction codes produce a `binder_txn_info` with populated header fields (`code`, `flags`, `interface`, `target_handle`) but empty `intent` fields and unparsed `raw_parcel`.

**Mitigation:** Add parsers for `ContentProvider` queries (`IContentProvider` codes 1–3) and `PackageManager` calls as needed.

### `DECISION_MODIFY`

In-flight Parcel modification is not implemented. It requires writing to the target process's address space, which is unavailable without `process_vm_readv`. The decision engine supports only ALLOW and DENY.

**Future path:** A modified Zygote hook could install a writable memfd before the target launches, establishing a shared memory region that sidesteps the SELinux constraint.

### Reply Capture

Only outbound transactions (`BC_TRANSACTION`) are intercepted. Binder replies (`BC_REPLY`) are allowed through without inspection. A second eBPF program attached to `raw_syscalls/sys_exit` could capture reply Parcels for audit purposes.

### Multi-Instance

The current design assumes a single target process. Running two instances of the daemon against different targets would require separate pinned map paths and separate cgroup attachments. The implementation does not prevent this but does not explicitly support it either.
