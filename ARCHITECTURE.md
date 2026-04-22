# Architecture

## Overview

The system is split into three parts:

1. `demoapp`
2. `policydaemon`
3. `binder_monitor_loader`

The design goal is:

- `demoapp` creates the seccomp listener
- `binder_monitor_loader` owns seccomp notification handling after fd handoff
- `policydaemon` is primarily a UI/control process

## Data flow

```text
demoapp
  -> installs seccomp user-notify filter
  -> forks child
  -> child issues raw Binder ioctl(BINDER_WRITE_READ)
  -> passes seccomp listener fd to policydaemon over AIDL

policydaemon
  -> forwards listener fd to binder_monitor_loader over Unix socket + SCM_RIGHTS
  -> asks loader for pending requests
  -> shows allow/deny UI
  -> sends allow/deny decisions back to loader

binder_monitor_loader
  -> loads and owns eBPF programs/maps
  -> arms target cgroup monitoring
  -> receives seccomp notifications with SECCOMP_IOCTL_NOTIF_RECV
  -> looks up Binder metadata from txn_map
  -> waits for policy decision
  -> sends seccomp response with SECCOMP_IOCTL_NOTIF_SEND
```

## Components

### demoapp

Responsibilities:

- install seccomp filter for `ioctl(BINDER_WRITE_READ)`
- fork the demo child
- trigger the child after registration is complete
- transfer the seccomp listener fd to `policydaemon`
- wait for child completion
- launch a visible browser intent after allow, for demo effect

Important property:

- `demoapp` no longer performs local seccomp `RECV`/`SEND`

### policydaemon

Responsibilities:

- receive session registration from `demoapp`
- forward the listener fd to `binder_monitor_loader`
- poll loader-owned pending state
- render pending requests in the UI
- return allow/deny decisions to the loader
- expose debug state through content providers and adb-triggerable commands

Important property:

- `policydaemon` does not own the seccomp listener lifecycle after handoff
- `policydaemon` is the user decision point, not the seccomp execution point

### binder_monitor_loader

Responsibilities:

- run as root
- load `binder_monitor.bpf.o`
- pin and manage BPF maps under `/sys/fs/bpf/binder_monitor`
- listen on the abstract Unix socket `@binder_monitor_proxy`
- accept listener fds from `policydaemon`
- maintain per-session seccomp state
- receive seccomp notifications
- enrich pending requests from `txn_map`
- apply allow/deny decisions

Important property:

- this daemon is the seccomp broker

## BPF role

The eBPF program monitors Binder traffic by tracing syscall entry for `ioctl`.

It records matching `BINDER_WRITE_READ` transactions into `txn_map`, keyed by thread id.

Current intent:

- seccomp suspends the Binder ioctl
- loader receives the seccomp notification
- loader looks up Binder transaction context in `txn_map`
- `policydaemon` presents the request to the user

## Session model

The current loader implementation uses per-client session state.

Each proxy connection from `policydaemon` owns:

- one active seccomp listener fd
- one worker thread
- one pending request state machine
- one target cgroup registration

This was introduced to fix repeated demo runs without restarting the loader.

## Current limitations

- Binder-derived metadata is not yet reliably populated in the pending UI
  - seccomp interception works
  - allow/deny flow works
  - repeated runs work
  - but `binder_interface`, `intent_action`, and `intent_uri` are often empty

So the control-plane architecture is working, while the Binder metadata enrichment path still needs work.
