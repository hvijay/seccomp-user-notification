#!/system/bin/sh
set -eu

LOADER_BIN="/data/local/tmp/binder_monitor_loader"
BPF_OBJ="/data/local/tmp/binder_monitor.bpf.o"
PIDFILE="/data/local/tmp/binder_monitor_loader.pid"

DEMO_PKG="com.example.seccomp.demoapp"
DEMO_ACTIVITY="com.example.seccomp.demoapp/.MainActivity"
DAEMON_PKG="com.example.seccomp.policydaemon"
DAEMON_SERVICE="com.example.seccomp.policydaemon/.PolicyDaemonService"

if [ ! -x "$LOADER_BIN" ]; then
  echo "missing loader: $LOADER_BIN" >&2
  exit 1
fi

if [ ! -f "$BPF_OBJ" ]; then
  echo "missing bpf object: $BPF_OBJ" >&2
  exit 1
fi

am force-stop "$DEMO_PKG" || true
am force-stop "$DAEMON_PKG" || true
logcat -c || true

if [ -f "$PIDFILE" ]; then
  OLD_PID="$(cat "$PIDFILE" 2>/dev/null || true)"
  if [ -n "${OLD_PID:-}" ]; then
    su root kill "$OLD_PID" 2>/dev/null || true
  fi
  rm -f "$PIDFILE"
fi

su root pkill -f binder_monitor_loader 2>/dev/null || true
sleep 1

su root sh -c "
  nohup \"$LOADER_BIN\" daemon >/data/local/tmp/loader_daemon.log 2>&1 &
  echo \$! > \"$PIDFILE\"
"

sleep 1

if [ -f "$PIDFILE" ]; then
  PID="$(cat "$PIDFILE" 2>/dev/null || true)"
  echo "loader pid: ${PID:-unknown}"
fi

am start-foreground-service -n "$DAEMON_SERVICE"
sleep 1
am start -n "$DEMO_ACTIVITY"

echo ""
echo "Demo is set up."
echo "Use the GUI now:"
echo "  1. Bring demoapp to foreground"
echo "  2. Tap Start"
echo "  3. Allow/Deny in policydaemon"
echo ""
echo "Logs:"
echo "  logcat -s SeccompDemoJNI SeccompPolicyJNI PolicyDaemonService"
echo "  cat /data/local/tmp/loader_daemon.log"
