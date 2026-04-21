# Context Handoff

## Repo state

- Repo: `/home/hayawardh/git/seccomp-user-notification`
- Branch: `master`
- Last commit: `48df96f` (`Checkpoint Binder LSM monitor prototype`)
- All current work is **uncommitted**

## Architecture overview

```
demoapp (JNI)
  └─ installs seccomp BINDER_WRITE_READ filter on forked child
  └─ forks child, child waits on go-pipe
  └─ calls daemon.registerSession(sessionId, listenerFd, description, myPid)
       └─ policydaemon JNI: nativeStartListener()
            └─ connects to /data/local/tmp/binder_monitor_proxy.sock
            └─ sends PROXY_MSG_SET_TARGET(myPid)  ← arms BPF cgroup filter
  └─ after registerSession returns, triggers child via go-pipe
  └─ child opens /dev/binder, issues raw BC_TRANSACTION ioctl(BINDER_WRITE_READ)
       └─ BPF tracepoint fires at sys_enter → stores to txn_map[child_tid]
       └─ seccomp filter fires → child frozen
  └─ policydaemon ListenerMain receives SECCOMP_IOCTL_NOTIF_RECV
       └─ calls LookupTransactionForTid(proxy_fd, request.pid)
            └─ sends PROXY_MSG_LOOKUP_TID(tid) to loader proxy
            └─ loader looks up txn_map[tid], returns binder_txn_info
       └─ if found → DeliverNotification → UI shows allow/deny
       └─ if not found → SECCOMP_USER_NOTIF_FLAG_CONTINUE (auto-allow)
```

## Components

### kernel/binder_monitor.bpf.c

- Attached to `tracepoint/raw_syscalls/sys_enter`
- Filters: ARM64 ioctl nr (29), cgroup check, BINDER_WRITE_READ cmd, BC_TRANSACTION bcmd
- Cgroup filter: reads `target_cgroup_map[0]` (u64); 0 = monitoring disabled
- On match: reads bwr struct, reads BC_TRANSACTION txn, parses parcel, writes to `txn_map[tid]`
- Maps:
  - `target_cgroup_map` (ARRAY, 1 entry, u32→u64)
  - `scratch` (PERCPU_ARRAY, scratch space)
  - `txn_map` (HASH, max 64 entries, keyed by u32 tid)
- Currently has `bpf_printk` debug statements at cgroup check and txn record points

### loader/src/binder_monitor_loader.c

- Runs as root daemon: `adb shell "su root sh -c 'nohup /data/local/tmp/binder_monitor_loader daemon > /data/local/tmp/loader_daemon.log 2>&1 &'"`
- Loads `binder_monitor.bpf.o`, starts with `target_cgroup_id=0` (idle)
- Pins maps and link under `/sys/fs/bpf/binder_monitor/`
- Listens on `/data/local/tmp/binder_monitor_proxy.sock`
- Proxy protocol (framed, over persistent TCP-like Unix stream):
  - `PROXY_MSG_SET_TARGET (0x01)` + u32 pid → resolves cgroup, updates `target_cgroup_map`, returns u8 ok
  - `PROXY_MSG_LOOKUP_TID (0x02)` + u32 tid → looks up `txn_map[tid]`, returns u8 found + binder_txn_info

### policydaemon/src/main/cpp/seccomp_policy_jni.cpp

- `nativeStartListener(sessionId, fd, targetPid)`:
  - Connects to proxy socket
  - Sends `PROXY_MSG_SET_TARGET(targetPid)`
  - Stores session in `g_sessions`, starts `ListenerMain` thread
- `ListenerMain`: loops on `SECCOMP_IOCTL_NOTIF_RECV`, calls `LookupTransactionForTid` via proxy, auto-allows if not found, delivers to Java if found
- `nativeStopListener`: sends `PROXY_MSG_SET_TARGET(0)` before closing
- **fdsan fix**: JNI never closes the listener fd on failure paths; Kotlin closes it in the `!ok` branch

### demoapp/src/main/cpp/seccomp_demo_jni.cpp

- `installFilterForkAndTriggerIntent()`:
  - Installs `SECCOMP_RET_USER_NOTIF` filter on `ioctl(BINDER_WRITE_READ)`
  - Forks child; child waits on go-pipe
  - Returns `[listenerFd, childPid, resultReadFd, goWriteFd]`
- `DoBinderTransaction()` (child side):
  - Reads go-pipe (waits for BPF to be armed)
  - Prints own pid + `/proc/self/cgroup` to result pipe (debug)
  - Opens `/dev/binder`, builds raw `BC_TRANSACTION` parcel
  - Parcel layout: `strict_mode(u32) | work_source_uid(u32) | interface(str16) | action(str16) | uri(str16) | pkg(str16)`
  - Calls `ioctl(BINDER_WRITE_READ)` → intercepted by seccomp
- `triggerChild(goWriteFd)`: unblocks the waiting child after session registration
- **go-pipe purpose**: ensures `SET_TARGET` completes and BPF filter is armed before child makes ioctl

### demoapp/src/main/java/.../MainActivity.kt

- Passes `android.os.Process.myPid()` (not child PID) to `registerSession` so loader targets the demoapp's stable cgroup (which child inherits at fork)
- After successful `registerSession`: calls `NativeSeccompBridge.triggerChild(goWriteFd)`
- After failed `registerSession`: also calls `triggerChild` to unblock and discard child

## Build commands

```bash
# BPF object
bash scripts/build_bpf.sh
# Output: kernel/binder_monitor.bpf.o

# Loader binary (root daemon)
bash scripts/build_loader.sh
# Output: loader/out/android-arm64/binder_monitor_loader

# Android apps
/tmp/gradle-8.7/bin/gradle :demoapp:assembleDebug
/tmp/gradle-8.7/bin/gradle :policydaemon:assembleDebug
```

## Deploy sequence

```bash
# Push BPF + loader
adb push kernel/binder_monitor.bpf.o /data/local/tmp/
adb push loader/out/android-arm64/binder_monitor_loader /data/local/tmp/
adb shell su root chmod +x /data/local/tmp/binder_monitor_loader

# Start loader daemon (must be root, must persist across adb disconnect)
adb shell su root pkill -f binder_monitor_loader
adb shell "su root sh -c 'nohup /data/local/tmp/binder_monitor_loader daemon > /data/local/tmp/loader_daemon.log 2>&1 &'"

# Install APKs
adb install -r demoapp/build/outputs/apk/debug/demoapp-debug.apk
adb install -r policydaemon/build/outputs/apk/debug/policydaemon-debug.apk
```

## Device state

- Attached Android device via adb
- Rooted (su root works)
- Android 15 debug kernel, BTF present, bpffs mounted, cgroupv2 available
- cgroupv2 NOT mounted at /sys/fs/cgroup directly — it's a hybrid v1/v2 setup:
  - v2 (unified): `0::/apps/uid_XXXXX/pid_YYYYY`
  - v1 controllers: cpuset, cpu, cpuacct, blkio, freezer
  - Loader path: `/sys/fs/cgroup` + path from `0::` line in `/proc/PID/cgroup`

## Current status

### What works

- BPF loads, attaches, fires ✓
- Loader daemon receives `SET_TARGET`, resolves cgroup id, updates `target_cgroup_map` ✓
- Cgroup ID comparison in BPF working — confirmed via `bpf_printk`:
  - `binder_monitor: ioctl cgroup cur=32681 target=32681` (for demoapp's own threads) ✓
- `BINDER_WRITE_READ = 0xc0306201` matches correctly ✓
- `BC_TRANSACTION = 0x40406300` recorded for demoapp's own binder calls ✓
- seccomp filter intercepts child's `ioctl(BINDER_WRITE_READ)` (child gets auto-allowed) ✓
- go-pipe timing: child waits for BPF to be armed before making ioctl ✓
- fdsan double-close crash fixed ✓
- Raw Binder transaction works (no am start, no SecurityException) ✓

### Current blocker

**The BPF does not record the forked child's `BINDER_WRITE_READ` ioctl.**

Evidence:
- `LookupTransactionForTid` returns `found=false` → seccomp auto-allows via `SECCOMP_USER_NOTIF_FLAG_CONTINUE`
- Trace shows NO `binder_monitor: ioctl cgroup cur=32681` entries for the child's TID
- Yet the child IS in the correct cgroup:
  - Child (e.g. pid=23298) cgroup from `/proc/self/cgroup`: `0::/apps/uid_10402/pid_23228`
  - Demoapp (pid=23228) cgroup: same path → id=32765
  - Loader confirmed: `proxy: monitoring pid=23228 cgroup=/sys/fs/cgroup/apps/uid_10402/pid_23228 id=32765`

### Hypotheses for child's ioctl not appearing in trace

1. **`bpf_printk` per-CPU buffer overflow**: so many ioctls from other processes hit the cgroup check that the child's printk is dropped from the ring buffer before we read it — but this wouldn't explain why `txn_map` has no entry for the child's TID
2. **`bpf_map_update_elem` fails silently**: txn_map is full (64 entries, hash map) when child's ioctl fires — other threads from demoapp/RenderThread are flooding it
3. **`sys_enter` tracepoint fires AFTER seccomp on this kernel**: if seccomp suspends the child before `sys_enter` fires, the BPF never runs for that ioctl
4. **Child is moved to a new cgroup between the debug print and the actual ioctl**: `DoBinderTransaction` prints cgroup, then opens `/dev/binder`, then calls `ioctl(BINDER_VERSION)`, then `ioctl(BINDER_SET_MAX_THREADS)`, then `ioctl(BINDER_WRITE_READ)` — Android could move the child during this window

### Most likely root cause

Hypothesis 3 (tracepoint vs seccomp ordering) is most concerning. On some kernels, seccomp runs before the raw_syscalls tracepoint. If so, the BPF program never fires for syscalls that seccomp intercepts.

### Suggested next investigation

1. **Verify ordering**: Add a BPF program that fires on `raw_syscalls/sys_exit` too, and check if the child's ioctl appears in `sys_exit` after being released by the policydaemon. If `sys_exit` fires but `sys_enter` didn't record → ordering issue.

2. **Check txn_map from root immediately after demo trigger**:
   ```bash
   adb shell su root bpftool map dump pinned /sys/fs/bpf/binder_monitor/txn_map
   ```
   If child's tid is in the map but lookup fails → protocol issue in loader proxy.
   If child's tid is NOT in the map → BPF never fired for it.

3. **Add bpf_printk with no cgroup filter** (temporarily set cgroup filter to match all):
   Change `target_cgroup_id == 0 → return 0` to log all ioctl syscalls → confirm BPF fires for child.

4. **Alternative hook**: Use `kprobe/binder_ioctl` instead of `raw_syscalls/sys_enter` — kprobes fire inside the kernel after seccomp has already allowed the syscall to proceed, so ordering is not an issue.

## Pinned files on device

- `/data/local/tmp/binder_monitor.bpf.o`
- `/data/local/tmp/binder_monitor_loader`
- `/data/local/tmp/binder_monitor_proxy.sock` (runtime, created by loader daemon)
- `/data/local/tmp/loader_daemon.log`
- `/sys/fs/bpf/binder_monitor/link`
- `/sys/fs/bpf/binder_monitor/txn_map`
- `/sys/fs/bpf/binder_monitor/target_cgroup_map`
</content>
</invoke>