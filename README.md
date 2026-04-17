# Android seccomp user-notify demo

This project sets up an end-to-end Android demo with two apps:

- `demoapp`: installs a seccomp user-notify filter from native code, forks a child, and has the child issue an `openat()` syscall that gets trapped.
- `policydaemon`: exports a foreground service that receives the listener FD over Binder, blocks on seccomp notifications in native code, and lets the user allow or deny each intercepted syscall from the UI.

## Project layout

- `shared`: shared AIDL contract and constants
- `demoapp`: trigger app
- `policydaemon`: policy daemon app

## Flow

1. Launch `policydaemon` once so its activity is available.
2. Open `demoapp` and tap `Bind daemon`.
3. Tap `Install filter + fork child`.
4. `demoapp` installs a seccomp filter returning `SECCOMP_RET_USER_NOTIF` for `openat`.
5. The native helper thread forks a child.
6. The child calls `openat("/proc/version")`.
7. The kernel delivers the seccomp notification to the listener FD.
8. `demoapp` sends that listener FD to `policydaemon` using Binder.
9. `policydaemon` shows the pending request and lets the user allow or deny it.

## Android and kernel assumptions

- The device kernel must support seccomp filter user notifications (`SECCOMP_FILTER_FLAG_NEW_LISTENER`).
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
4. Tap `Install filter + fork child`.
5. In `policydaemon`, choose `Allow` or `Deny` for the pending `openat()` request.

## Behavior notes

- The demo filter only traps `openat`.
- Allow uses `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.
- Deny returns `EPERM`.
- The helper installs the filter on a short-lived native thread so the app's main/UI threads are not left permanently filtered.
