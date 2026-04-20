# Android seccomp user-notify demo

This project sets up an end-to-end Android demo with two apps:

- `demoapp`: installs a seccomp user-notify filter from native code, forks a child, and has the child issue a Binder-backed `am broadcast` Intent from native code so the `ioctl(BINDER_WRITE_READ)` path gets trapped.
- `policydaemon`: exports a foreground service that receives the listener FD over Binder, blocks on seccomp notifications in native code, and correlates each trapped Binder ioctl with `binder_txn_info` metadata from a pinned eBPF `txn_map` when that kernel-side monitor is present.

## Project layout

- `shared`: shared AIDL contract and constants
- `demoapp`: trigger app
- `policydaemon`: policy daemon app
- `common/shared_types.h`: contract shared by the daemon-side native code and the design-aligned eBPF monitor
- `kernel/binder_monitor.bpf.c`: scaffold for the per-cgroup Binder monitor described in `binder_monitor_design.md`

## Flow

1. Launch `policydaemon` once so its activity is available.
2. Open `demoapp` and tap `Bind daemon`.
3. Tap `Install filter + fork native Binder child`.
4. `demoapp` installs a seccomp filter returning `SECCOMP_RET_USER_NOTIF` for `ioctl(BINDER_WRITE_READ)`.
5. The native helper thread forks a child.
6. The child execs `/system/bin/am broadcast ...` from native code.
7. The kernel delivers the seccomp notification to the listener FD when the child hits Binder.
8. `demoapp` sends that listener FD plus the child PID to `policydaemon` using Binder.
9. `policydaemon` optionally looks up `binder_txn_info` for the trapped TID from `/sys/fs/bpf/binder_monitor/txn_map`.
10. `policydaemon` shows the pending request and lets the user allow or deny it.

## Android and kernel assumptions

- The device kernel must support seccomp filter user notifications (`SECCOMP_FILTER_FLAG_NEW_LISTENER`).
- For Binder transaction correlation, a privileged kernel-side eBPF monitor must pin `txn_map` at `/sys/fs/bpf/binder_monitor/txn_map`.
- The app process must be allowed to call `seccomp()` and `prctl(PR_SET_NO_NEW_PRIVS, 1)`.
- This demo is intended for modern arm64 Android devices or emulators with a recent kernel.
- `policydaemon` runs as a foreground service so it can keep listening while its UI is backgrounded.

## Build

This workspace does not include a Gradle wrapper. The examples below use the local Gradle distribution at `/tmp/gradle-8.7/bin/gradle`.

Build both debug APKs:

```bash
/tmp/gradle-8.7/bin/gradle :policydaemon:assembleDebug :demoapp:assembleDebug
```

APK outputs:

- `policydaemon/build/outputs/apk/debug/policydaemon-debug.apk`
- `demoapp/build/outputs/apk/debug/demoapp-debug.apk`

## Install

Install directly with `adb install -r`:

```bash
adb install -r policydaemon/build/outputs/apk/debug/policydaemon-debug.apk
adb install -r demoapp/build/outputs/apk/debug/demoapp-debug.apk
```

If you prefer pushing the APKs to the device first:

```bash
adb push policydaemon/build/outputs/apk/debug/policydaemon-debug.apk /data/local/tmp/
adb push demoapp/build/outputs/apk/debug/demoapp-debug.apk /data/local/tmp/
adb shell pm install -r /data/local/tmp/policydaemon-debug.apk
adb shell pm install -r /data/local/tmp/demoapp-debug.apk
```

## Run

1. Start `policydaemon`.
2. Start `demoapp`.
3. In `demoapp`, tap `Bind daemon`.
4. Tap `Install filter + fork native Binder child`.
5. In `policydaemon`, choose `Allow` or `Deny` for the pending Binder `ioctl()` request.

## Behavior notes

- The demo filter only traps `ioctl(BINDER_WRITE_READ)`.
- Allow uses `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.
- Deny returns `EPERM`.
- The helper installs the filter on a short-lived native thread so the app's main/UI threads are not left permanently filtered.
- If the pinned eBPF map is not available, the daemon still shows the seccomp stop, child TID, and target cgroup path, but Binder parcel metadata will be absent.
