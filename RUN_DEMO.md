# Run Demo via ADB

## Install

```bash
adb install -r demoapp/build/outputs/apk/debug/demoapp-debug.apk
adb install -r policydaemon/build/outputs/apk/debug/policydaemon-debug.apk
```

## Start the policy daemon service

```bash
adb shell am start-foreground-service -n com.example.seccomp.policydaemon/.PolicyDaemonService
```

## Trigger the demo app without UI interaction

```bash
adb shell am start -n com.example.seccomp.demoapp/.MainActivity -a com.example.seccomp.demoapp.action.RUN_DEMO
```

## Allow the pending seccomp request

```bash
adb shell am start-foreground-service \
  -n com.example.seccomp.policydaemon/.PolicyDaemonService \
  -a com.example.seccomp.policydaemon.action.COMMAND \
  --es decision allow
```

## Deny the pending seccomp request

```bash
adb shell am start-foreground-service \
  -n com.example.seccomp.policydaemon/.PolicyDaemonService \
  -a com.example.seccomp.policydaemon.action.COMMAND \
  --es decision deny
```

## Target a specific pending notification

```bash
adb shell am start-foreground-service \
  -n com.example.seccomp.policydaemon/.PolicyDaemonService \
  -a com.example.seccomp.policydaemon.action.COMMAND \
  --es decision allow \
  --es notification_key 'session-...:123'
```

## Query demo app status programmatically

```bash
adb shell content query --uri content://com.example.seccomp.demoapp.debug/status
adb shell content query --uri content://com.example.seccomp.demoapp.debug/events
```

## Query policy daemon status and pending requests programmatically

```bash
adb shell content query --uri content://com.example.seccomp.policydaemon.debug/status
adb shell content query --uri content://com.example.seccomp.policydaemon.debug/events
adb shell content query --uri content://com.example.seccomp.policydaemon.debug/pending
```

## Query native / loader logs programmatically

```bash
adb logcat -d -s SeccompPolicyJNI PolicyDaemonService
adb shell cat /data/local/tmp/loader_daemon.log
adb shell su root bpftool map dump pinned /sys/fs/bpf/binder_monitor/txn_map
```
