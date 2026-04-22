# Context Handoff

## Repo state

- Repo: `/home/hayawardh/git/seccomp-user-notification`
- Branch: `master`
- Current commit: see `git log -1`
- Build tool: Gradle at `/tmp/gradle-8.7/bin/gradle` (NOT on PATH)

## Current architecture

```text
demoapp
  - AI-agent simulation UI ("Atlas")
  - installs syscall-specific seccomp user-notify filter per action
  - forks child that issues the intercepted syscall
  - transfers seccomp listener fd to policydaemon over AIDL
  - waits for child result only

policydaemon
  - UI/control process
  - receives listener fd from demoapp
  - forwards listener fd to binder_monitor_loader over Unix socket + SCM_RIGHTS
  - polls loader for pending requests; shows allow/deny UI
  - parses raw parcel bytes with android.os.Parcel (libbinder) in Java
  - sends decisions back to loader

binder_monitor_loader
  - root daemon
  - loads and owns the eBPF programs/maps
  - arms target cgroup monitoring (SET_TARGET)
  - owns seccomp RECV/SEND after fd handoff
  - enriches pending request with syscall-specific metadata via process_vm_readv
  - holds per-session pending seccomp state
```

## Intercepted syscalls

Three operation kinds are supported, distinguished by `operation_kind` in `proxy_pending_request`:

| `operation_kind` | Syscall | Loader enrichment | Policydaemon display |
|---|---|---|---|
| `OP_KIND_BINDER` (1) | `ioctl(BINDER_WRITE_READ)` | raw parcel bytes via `process_vm_readv` | IContentProvider.query, startActivity, etc. via libbinder |
| `OP_KIND_FILE_OPEN` (2) | `openat` | `file_path` (from args[1] ptr), `open_flags`/`open_mode` | `open(path, O_RDONLY\|…)` |
| `OP_KIND_EXEC` (3) | `execve` | `file_path` (from args[0] ptr), `exec_argv` summary (up to 4 args from args[1] ptr-array) | `execve(path, [arg0, arg1, …])` |

## Parsing architecture (important design constraint)

- **BPF**: captures raw parcel bytes + transaction metadata only. No parcel header or intent parsing in BPF.
- **Loader**: enriches file path / argv for non-Binder syscalls via `process_vm_readv`. For Binder, transports raw parcel bytes only — no C-level parcel parsing.
- **Policydaemon**: all Binder parcel parsing done exclusively in Java using `android.os.Parcel` (libbinder wrapper). Parsing is AIDL-interface-driven, not demoapp-specific.

This matters for production: the monitored app is treated as a black box. The policydaemon must parse what arrives from the loader, not make assumptions about how the app writes it.

## What is verified working

- Seccomp interception of Binder ioctl, openat, and execve
- `OP_KIND_BINDER`: shows `IContentProvider.query(callingPkg=…, uri=content://com.android.calendar/events)` with calendar-read warning
- `OP_KIND_FILE_OPEN`: shows `open(path, O_RDONLY)` with semantic file warning
- `OP_KIND_EXEC`: shows `execve(/system/bin/curl, [curl, https://example.com/])` with curl warning
- Allow/deny flow end-to-end for all three operation kinds
- Repeated demo runs without restarting loader
- Calling-package resolved from AIDL binder UID (`Binder.getCallingUid()`) or ActivityManager fallback

## Key implementation details

### Binder parcel parsing (policydaemon Java)

Files:
- `policydaemon/…/BinderParcelDecoder.kt` — entry point; unmarshalls raw bytes with `Parcel.unmarshall()`, reads header, dispatches to per-interface parsers
- `policydaemon/…/BinderCallInfo.kt` — data classes for decoded call + args
- `policydaemon/…/BinderInterfaceRegistry.kt` — maps (interface, txCode) → method name via reflection; falls back to hardcoded table when hidden-API blocks reflection

Header layout (Android 9+):
```
[int32]  strict-mode policy
[int32]  work-source UID       ← only if API >= 28 (Build.VERSION_CODES.P)
[String16] interface descriptor
[AIDL params follow…]
```

Known interfaces and hardcoded transaction codes:
- `android.content.IContentProvider`: query(1), insert(3), update(6), delete(5), …
- `android.app.IActivityManager`: startActivity(1), broadcastIntent(14), startService(25), bindService(27)
- `android.app.IActivityTaskManager`: startActivity(1), startActivityAsUser(2)

### Samsung `Uri.CREATOR` bug

On Samsung ROM, `StringUri.readFrom(Parcel)` calls `readString8` (reads raw bytes, null-terminated) instead of `readString16`. UTF-16LE null bytes after each ASCII character truncate the result to the first character (e.g. `"content://..."` → `"c"`).

**Fix** (`BinderParcelDecoder.readUri`): manually read the type int, and for StringUri (type=1) call `p.readString()` directly then `Uri.parse()`. For other types fall through to `Uri.CREATOR.createFromParcel()`.

### MakePendingArray (JNI Object[15])

```
[0]  notification_id (String)
[1]  pid (String)
[2]  syscall_nr (String)
[3]  operation_kind (String: 1=binder, 2=file_open, 3=exec)
[4]  ioctl_cmd (String)
[5]  binder_code (String)
[6]  target_handle (String)
[7]  parcel_truncated (String: "true"/"false")
[8]  open_flags (String)
[9]  open_mode (String)
[10] file_path (String)
[11] exec_argv summary (String)
[12] txn.data_size (String)
[13] raw parcel bytes (ByteArray, null if nothing captured)
[14] captured byte count (String)
```

### Loader enrichment for openat/execve

`fill_pending_request()` routes by `notif->data.nr`:
- `__NR_openat`: `enrich_open_from_process_vm` — reads path from `args[1]` pointer, flags from `args[2]`, mode from `args[3]`
- `__NR_execve`: `enrich_exec_from_process_vm` — reads path from `args[0]`, walks argv pointer array at `args[1]` (up to 4 entries, each via `process_vm_readv`)

### Calling-package resolution

Priority order in `SeccompRepository`:
1. `sessionCallerPackages[sessionId]` — set at registration time via `Binder.getCallingUid()` + `packageManager.getPackagesForUid()`
2. `ActivityManager.runningAppProcesses` lookup by PID
3. `callingPackage`/`callingPkg` string arg from parsed Binder call

### Demoapp demo actions

| Button | Kind | Syscall | Example output |
|---|---|---|---|
| Print calendar | Binder | ioctl | IContentProvider.query(…, uri=content://…/events) |
| Open browser | Binder | ioctl | IActivityManager.startActivity(intent={action=VIEW …}) |
| Send email | Binder | ioctl | IActivityManager.startActivity(intent={action=SENDTO …}) |
| Read CONTEXT.md | File open | openat | open(…/files/workspace/CONTEXT.md, O_RDONLY) |
| Execute curl | Exec | execve | execve(/system/bin/curl, [curl, https://example.com/]) |

Workspace CONTEXT.md is created by `ensureWorkspaceContextFile()` on first launch at `filesDir/workspace/CONTEXT.md`.

## Known issues / TODOs

- BPF `parse_parcel_header` and `parse_known_intent_fields` are still called in `binder_monitor.bpf.c` — these fill `txn->interface` and `txn->intent.*` fields which the policydaemon no longer reads (it parses from raw bytes). They are harmless but add BPF complexity. Should be removed in a future cleanup (requires rebuilding the BPF `.o` file).
- HierarchicalUri (type=3) and OpaqueUri (type=2) are not manually decoded; `Uri.CREATOR.createFromParcel` is used for those types. May be broken on Samsung for the same reason as StringUri. Not encountered in practice yet.
- `resolveCallingPackage` via `ActivityManager.runningAppProcesses` may be empty once the process is frozen.

## Useful commands

### Build

```bash
# BPF (requires clang + Android NDK — see scripts/build_bpf.sh)
bash scripts/build_bpf.sh

# Loader (static ARM64 binary)
bash scripts/build_loader.sh

# APKs
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

### Run

```bash
# Start loader daemon (keep running across demo runs)
adb shell su root /data/local/tmp/binder_monitor_loader daemon

# Start apps
adb shell am start -n com.example.seccomp.policydaemon/.MainActivity
adb shell am start -n com.example.seccomp.demoapp/.MainActivity -a com.example.seccomp.demoapp.action.RUN_DEMO
```

### Inspect

```bash
adb shell content query --uri content://com.example.seccomp.policydaemon.debug/status
adb shell content query --uri content://com.example.seccomp.policydaemon.debug/pending
adb shell content query --uri content://com.example.seccomp.demoapp.debug/status
adb logcat -s "BinderParcelDecoder:D" "SeccompRepository:D" "SeccompPolicyJNI:W"
adb shell su root bpftool map dump pinned /sys/fs/bpf/binder_monitor/txn_map
```
