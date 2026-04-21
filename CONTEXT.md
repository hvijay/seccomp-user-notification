# Context Handoff

## Repo state

- Repo: `/home/hayawardh/git/seccomp-user-notification`
- Branch: `master`
- Current commit: `04a881b` (`Fix loader session cleanup for repeated demo runs`)
- Worktree status at handoff: `CONTEXT.md` modified, not yet committed

## Current architecture

This is now closer to the intended production split:

```text
demoapp
  - installs seccomp user-notify filter
  - forks child that issues the raw Binder ioctl
  - transfers seccomp listener fd to policydaemon over AIDL
  - waits for child result only

policydaemon
  - UI/control process only
  - receives listener fd from demoapp
  - forwards listener fd to binder_monitor_loader over Unix socket + SCM_RIGHTS
  - polls loader for pending requests
  - shows allow/deny UI
  - sends decisions back to loader

binder_monitor_loader
  - root daemon
  - loads and owns the eBPF programs/maps
  - arms target cgroup monitoring
  - owns seccomp RECV/SEND after fd handoff
  - looks up Binder metadata from txn_map
  - holds per-session pending seccomp state
```

## What is verified working

### End-to-end seccomp allow flow

Verified on the attached rooted device with `adb` only:

1. start long-lived `binder_monitor_loader daemon`
2. start `policydaemon`
3. run `demoapp`
4. loader receives seccomp notification for the child Binder ioctl
5. `policydaemon` shows a pending request
6. send `allow`
7. loader sends seccomp response
8. child completes and `demoapp` launches the visible browser action

Observed loader trace from a good run:

```text
proxy: monitoring pid=12399 cgroup=/sys/fs/cgroup/apps/uid_10339/pid_12399 id=28388
proxy: listener registered fd=8
proxy: worker started listener_fd=8 txn_map_fd=3
proxy: waiting for seccomp notification fd=8
proxy: received seccomp notification id=... pid=12473 nr=29 arg1=3224396289
proxy: pending notification id=... tid=12473 iface='' action='' uri=''
proxy: sending seccomp response id=... allow=1
proxy: waiting for seccomp notification fd=8
proxy: SECCOMP_IOCTL_NOTIF_RECV failed: No such file or directory
proxy: worker exiting
proxy: monitoring disabled
```

`policydaemon` showed:

```text
Pending Binder request from tid=12473 (target pid=12399). Tap allow or deny.
```

`demoapp` finished with:

```text
Binder VIEW transaction submitted (seccomp allowed).
```

### Repeated demo runs without restarting loader

This was the main verified fix in `04a881b`.

Tested sequence:

1. keep one long-lived loader instance running
2. run demo once and allow it
3. force-stop only `demoapp`
4. run demo again without restarting loader or `policydaemon`
5. allow again

Result:

- second run successfully created a fresh loader session
- second run surfaced a fresh pending request in `policydaemon`
- second run completed successfully after allow

Observed loader trace from second run:

```text
proxy: monitoring pid=12838 cgroup=/sys/fs/cgroup/apps/uid_10339/pid_12838 id=28444
proxy: listener registered fd=8
proxy: worker started listener_fd=8 txn_map_fd=3
proxy: waiting for seccomp notification fd=8
proxy: received seccomp notification id=... pid=12939 nr=29 arg1=3224396289
proxy: pending notification id=... tid=12939 iface='' action='' uri=''
proxy: sending seccomp response id=... allow=1
proxy: waiting for seccomp notification fd=8
proxy: SECCOMP_IOCTL_NOTIF_RECV failed: No such file or directory
proxy: worker exiting
proxy: monitoring disabled
```

So repeated runs now work.

## Main code shape

### Loader

File:

- `loader/src/binder_monitor_loader.c`

Important current behavior:

- each proxy client has its own `struct active_session`
- no more global singleton session state
- `REGISTER_LISTENER` starts a per-client worker thread
- worker thread does:
  - `SECCOMP_IOCTL_NOTIF_RECV`
  - lookup-and-delete from `txn_map`
  - hold pending request
  - wait for decision
  - `SECCOMP_IOCTL_NOTIF_SEND`
- client disconnect / unregister cleans up only that client session
- `SET_TARGET(0)` disables monitoring on session teardown

### Policydaemon

Files:

- `policydaemon/src/main/java/com/example/seccomp/policydaemon/SeccompRepository.kt`
- `policydaemon/src/main/java/com/example/seccomp/policydaemon/PolicyDaemonService.kt`
- `policydaemon/src/main/cpp/seccomp_policy_jni.cpp`

Important current behavior:

- receives listener fd from `demoapp`
- forwards it to loader using `PROXY_MSG_REGISTER_LISTENER`
- polls loader with `PROXY_MSG_GET_PENDING`
- sends decisions with `PROXY_MSG_SEND_DECISION`
- UI is black/green themed with allow/deny controls
- repeated runs are now working against one long-lived loader

### Demoapp

File:

- `demoapp/src/main/java/com/example/seccomp/demoapp/MainActivity.kt`

Important current behavior:

- no longer does local seccomp `RECV`/`SEND`
- creates seccomp listener fd and child
- registers session with `policydaemon`
- transfers listener ownership away
- waits for child result only
- after allow, launches visible browser `ACTION_VIEW`

## Remaining blocker

### Binder-derived metadata is still mostly blank

The policy flow works, but the user-facing Binder metadata shown in `policydaemon` is not yet trustworthy.

Current observed pending row fields:

```text
binder_interface=
binder_code=0
intent_action=
intent_uri=
```

Loader trace also shows:

```text
proxy: pending notification id=... tid=... iface='' action='' uri=''
```

So:

- seccomp interception works
- repeated runs work
- pending allow/deny UI works
- but `txn_map` enrichment is not reliably producing the expected `VIEW https://example.com/` metadata at decision time

This is the main remaining technical gap.

## Likely next debugging direction

Focus on why `fill_pending_request()` gets an empty `binder_txn_info` for the intercepted child tid.

Relevant code path:

1. BPF program writes `txn_map[tid]`
2. loader worker receives seccomp notif for pid/tid
3. `fill_pending_request()` does `sys_bpf_map_lookup_and_delete_elem(txn_map_fd, &pending->pid, &pending->txn)`
4. UI shows whatever came back

Potential causes to check:

- wrong key being used at lookup time
- `txn_map` entry not yet present when seccomp notification is received
- BPF parser not recognizing the current Binder parcel shape
- `lookup_and_delete` returning zeroed or partial data
- unrelated Binder traffic for the same process overwriting or racing before lookup

The current loader logging is useful for this and should probably stay until metadata is fixed:

- worker start
- wait for seccomp
- received seccomp notif
- pending notification with parsed iface/action/uri
- get-pending / send-decision logging

## Useful commands

### Build

```bash
bash scripts/build_bpf.sh
bash scripts/build_loader.sh
/tmp/gradle-8.7/bin/gradle :demoapp:assembleDebug :policydaemon:assembleDebug
```

### Deploy

```bash
adb push kernel/binder_monitor.bpf.o /data/local/tmp/
adb push loader/out/android-arm64/binder_monitor_loader /data/local/tmp/
adb shell su root chmod +x /data/local/tmp/binder_monitor_loader

adb install -r demoapp/build/outputs/apk/debug/demoapp-debug.apk
adb install -r policydaemon/build/outputs/apk/debug/policydaemon-debug.apk
```

### Start loader in foreground for debugging

This was the most reliable way to observe loader state:

```bash
adb shell su root /data/local/tmp/binder_monitor_loader daemon
```

### Start apps

```bash
adb shell am start-foreground-service -n com.example.seccomp.policydaemon/.PolicyDaemonService
adb shell am start -n com.example.seccomp.demoapp/.MainActivity -a com.example.seccomp.demoapp.action.RUN_DEMO
```

### Allow first pending request

```bash
adb shell am start-foreground-service \
  -n com.example.seccomp.policydaemon/.PolicyDaemonService \
  -a com.example.seccomp.policydaemon.action.COMMAND \
  --es decision allow
```

### Inspect app debug providers

```bash
adb shell content query --uri content://com.example.seccomp.demoapp.debug/status
adb shell content query --uri content://com.example.seccomp.demoapp.debug/events
adb shell content query --uri content://com.example.seccomp.policydaemon.debug/status
adb shell content query --uri content://com.example.seccomp.policydaemon.debug/pending
```

### Inspect BPF txn map

```bash
adb shell su root bpftool map dump pinned /sys/fs/bpf/binder_monitor/txn_map
```

## Summary

At this handoff point:

- production-like ownership split is implemented
- loader owns seccomp receive/respond
- policydaemon is effectively UI/control
- repeated runs are fixed and verified
- remaining blocker is Binder metadata enrichment, not the seccomp/session architecture
