## Codex → Claude (turn 1)

Current on-device result for the `__seccomp_filter` PoC:

- loader successfully loads and attaches `binder_monitor` as a `kprobe` program
- `bpftool prog show` lists:
  - `kprobe  name binder_monitor ... id 875 ... map_ids 264,268,265,266`
- seccomp user-notify path is working:
  - loader logs `proxy: received seccomp notification ... pid=19475 nr=29`
- policydaemon stays connected to `@binder_monitor_proxy`
- parent pid `19413` and child tid `19475` are in the same cgroup:
  - `/apps/uid_10347/pid_19413`
- but `txn_map` is empty at the same moment:
  - `bpftool map dump pinned /sys/fs/bpf/binder_monitor/txn_map` => `[]`
- and the loader logs pending requests with blank metadata:
  - `iface='' action='' uri=''`
- also, `trace` contains no `binder_monitor` / `seccomp_filter` / `recorded txn` printk lines at all

That makes me think the loaded kprobe is not actually firing on the seccomp user-notify path on this kernel, even though the symbol exists and the attach succeeds.

The BPF program currently assumes:
- kprobe target: `__seccomp_filter`
- `PT_REGS_PARM1(ctx)` = syscall nr
- `PT_REGS_PARM2(ctx)` = `const struct seccomp_data *`

Given the evidence above, my current suspicion ranking is:

1. `__seccomp_filter` is not reached on the effective path for this kernel/config
2. the probe is hit but on a different call pattern/signature than assumed, so we immediately return before any printk
3. less likely: printk visibility issue plus independent logic failure, though empty `txn_map` argues against that

My likely next step is to pivot the PoC hook from `__seccomp_filter` to `do_seccomp` and re-run the same device test.

Questions for you:

1. Do you agree that “loaded but never firing” is the most likely interpretation here?
2. If so, would you go directly to `do_seccomp`, or would you first instrument `__seccomp_filter` with a minimal entry counter map to rule out a silent early-return/signature issue?
3. If you know the likely arm64 signature shape for Samsung’s `__seccomp_filter` / `do_seccomp` on Android 6.1 kernels, that would help narrow the register assumptions.

## Codex → Claude (turn 2)

New concrete result from device instrumentation:

- `__seccomp_filter` definitely fires
- `PT_REGS_PARM1(ctx)` is plausibly the syscall nr, because the `ioctl==29` counter rises
- but no readable `struct seccomp_data *` is present in any of the likely argument registers I tried

Counter sweep on the live device after one run:

- key 0 = entry count: `17552`
- key 1 = `parm1 == ioctl(29)` count: `3113`
- key 2 = `bpf_probe_read_kernel(sd, x1)` success: `0`
- key 4 = `... from x2` success: `0`
- key 5 = `... from x3` success: `0`
- key 6 = `... from x4` success: `0`
- key 7 = all candidate pointer reads failed: `3116`

So this kernel is not exposing a dereferenceable `seccomp_data *` in the first four arm64 argument registers for the `__seccomp_filter` kprobe context, even though the function is clearly being entered.

That means:

1. `__seccomp_filter` as a plain kprobe is not enough for this PoC if we need syscall arg memory.
2. The remaining realistic seccomp-path options look like:
   - `do_seccomp`
   - a different seccomp-internal symbol closer to the actual `seccomp_data`
   - or abandoning `__seccomp_filter` and moving to a different hook type entirely

Given this result, my current inclination is to stop burning time on `__seccomp_filter` register archaeology and pivot the PoC to `do_seccomp` next.

If you have a better next seccomp-path symbol than `do_seccomp`, or you know where Samsung 6.1 keeps the `seccomp_data` pointer in this path, that would be useful.

## Claude → Codex (turn 2)

Good data — the absence of any `bpf_printk` lines in trace is the cleanest signal. The first printk in our BPF fires *before* the cgroup equality check (we print both values unconditionally), so if zero lines appear even when the target cgroup is armed, the kprobe entry is never reached. That makes **"attached but never firing"** the most likely interpretation. Agree on diagnosis #1.

**On `do_seccomp` vs counter-first approach**

My recommendation: skip the counter detour and go straight to alternative attach points. Here's why — the counter would only confirm "fires/doesn't fire", which we already know from the printk absence. Better to find the right symbol.

Candidate symbols in priority order (all should be in kallsyms on a 6.6 GKI-ish kernel):

1. **`seccomp_do_user_notification`** — called exactly when `SECCOMP_RET_USER_NOTIF` is the filter result, *before* the thread sleeps. Zero false positives. Fires in the child's context with user mm live. Best fit.

2. **`seccomp_run_filters`** — called from within `__seccomp_filter` to actually walk the filter chain. If `__seccomp_filter` isn't reached, this isn't either, but worth checking if it's a separate symbol.

3. **`__secure_computing`** — the caller of `__seccomp_filter`. Fires for every seccomp-checked syscall across the whole system; would need the ioctl-nr + cgroup pre-filter in the BPF to stay cheap.

Please run: `adb shell grep -E 'seccomp_do_user_notification|seccomp_run_filters|__secure_computing' /proc/kallsyms | head -10`

**On the `do_seccomp` suggestion from your turn**

`do_seccomp` is the `seccomp(2)` syscall handler (the one that installs filters). It fires when a process calls `prctl(PR_SET_SECCOMP, ...)` or `seccomp()`, not when filters run at syscall time. That's the wrong hook for our purpose.

**Alternative to BPF parcel reading: `process_vm_readv()` from the loader**

While we sort out the kprobe attach point, there's a parallel approach worth pursuing:

After the loader calls `SECCOMP_IOCTL_NOTIF_RECV`, the child is suspended in-kernel. `notif->data.args[2]` is the userspace pointer to `binder_write_read`. The loader (running as root) can call `process_vm_readv(notif->pid, ...)` to read the Binder transaction directly — no BPF, no ptrace. This is a separate syscall from ptrace and has its own permission model.

The user specifically asked about `pread()` on `/proc/pid/mem` vs `process_vm_readv()`. Both hit `ptrace_may_access()` internally on Linux but Android's CTS/CDD neverallow rules target `ptrace()` the syscall, not the internal `ptrace_may_access` helper. A root process should be able to call `process_vm_readv` on a child that it has a seccomp supervisor relationship with, as long as SELinux allows it. The loader's SELinux context would need to allow `process { ptrace }` on the target — which is what we need to verify.

**Concrete suggestion**:

In `fill_pending_request()` in `binder_monitor_loader.c`, after the txn_map lookup returns empty, try:

```c
if (notif->data.args[1] == BINDER_WRITE_READ) {
    struct binder_write_read bwr = {};
    struct iovec local_iov = { &bwr, sizeof(bwr) };
    struct iovec remote_iov = { (void *)notif->data.args[2], sizeof(bwr) };
    ssize_t n = process_vm_readv(notif->pid, &local_iov, 1, &remote_iov, 1, 0);
    if (n == sizeof(bwr) && bwr.write_size >= sizeof(uint32_t) + sizeof(struct binder_transaction_data)) {
        // read bcmd, then binder_transaction_data, parse interface/code
    }
}
```

This would let us get Binder metadata regardless of BPF probe status, and it's purely additive to the existing flow.

**Summary of asks**:

1. Check kallsyms for the three symbols above.
2. Try attaching to `seccomp_do_user_notification` first (most targeted), fall back to `__secure_computing`.
3. In parallel, prototype `process_vm_readv()` in `fill_pending_request()` — even a quick test that reads `bwr.write_size` and logs it would confirm whether the approach works on this device.

---

## Claude → Codex (turn 3)

**Root cause confirmed from kernel source (v6.6 `kernel/entry/common.c` + `kernel/seccomp.c`)**

Two facts the source makes unambiguous:

### 1. `trace_sys_enter` fires AFTER seccomp

```c
// kernel/entry/common.c  __syscall_enter_from_user_work()

/* Do seccomp after ptrace, to catch any tracer changes. */
if (work & SYSCALL_WORK_SECCOMP) {
    ret = __secure_computing(NULL);   // <-- seccomp runs here
    if (ret == -1L)
        return ret;                   // <-- returns if thread blocks (USER_NOTIF)
}

if (unlikely(work & SYSCALL_WORK_SYSCALL_TRACEPOINT))
    trace_sys_enter(regs, syscall);   // <-- NEVER reached if seccomp returns -1
```

The `raw_syscalls/sys_enter` tracepoint is unreachable for any syscall that gets blocked by `SECCOMP_RET_USER_NOTIF`. This is inherent to the design — not a Samsung quirk.

### 2. `__secure_computing(NULL)` passes NULL as the `seccomp_data *`

```c
// kernel/seccomp.c  __seccomp_filter()

static int __seccomp_filter(int this_syscall, const struct seccomp_data *sd,
                            const bool recheck_after_trace)
{
    struct seccomp_data sd_local;
    ...
    if (!sd) {
        populate_seccomp_data(&sd_local);  // <-- sd filled HERE, on stack
        sd = &sd_local;
    }
    filter_ret = seccomp_run_filters(sd, &match);
    ...
    case SECCOMP_RET_USER_NOTIF:
        seccomp_do_user_notification(this_syscall, match, sd);
```

At kprobe entry to `__seccomp_filter`: x1 (PARM2 = sd) = NULL. That's why all `bpf_probe_read_kernel` calls on x0–x4 fail for sd — x1 is literally null. The data is only populated *after* entry via `populate_seccomp_data`.

This also confirms: at `seccomp_run_filters` entry, x0 = valid `seccomp_data *` (on `__seccomp_filter`'s stack frame). At `seccomp_do_user_notification` entry, x2 = same valid pointer.

---

### What to hook instead

From kallsyms we have `__secure_computing` (exported). `seccomp_run_filters` and `seccomp_do_user_notification` are `static` — likely not in kallsyms on this device.

**Best available hook: `__secure_computing`**

Signature: `int __secure_computing(const struct seccomp_data *sd)` — but called as `__secure_computing(NULL)`, so x0 = NULL at entry too.

However, at the kprobe on `__secure_computing` we are in the current task's context with the full user pt_regs saved on the kernel stack. We can get the syscall arguments without reading `sd` at all:

```c
// In BPF kprobe on __secure_computing:
struct task_struct *task = bpf_get_current_task();
// Read ARM64 user pt_regs saved at syscall entry
// task->thread.cpu_context is kernel context; user regs are at task_pt_regs(task)
// On ARM64: struct pt_regs is at the top of the kernel stack
// Offset: thread_info is at stack base; pt_regs sits just above it
```

This requires CO-RE or hardcoded offsets for this kernel. Brittle.

---

### Recommended pivot: loader-side `process_vm_readv()`

We don't need BPF for the ioctl arguments at all — `SECCOMP_IOCTL_NOTIF_RECV` returns a `seccomp_notif` which embeds the full `seccomp_data`:

```c
struct seccomp_notif {
    __u64 id;
    __u32 pid;
    __u32 flags;
    struct seccomp_data data;   // .args[1] = ioctl cmd, .args[2] = binder_write_read *
};
```

The loader already has `notif->data.args[1]` (cmd) and `notif->data.args[2]` (the `binder_write_read *` userspace pointer). The child is suspended. We just need to read the Binder parcel from that pointer.

Implement in `fill_pending_request()` after the txn_map lookup:

```c
#include <sys/uio.h>

static void enrich_from_process_vm(struct proxy_pending_request *pending,
                                   const struct seccomp_notif *notif)
{
    if (notif->data.args[1] != BINDER_WRITE_READ)
        return;

    struct binder_write_read bwr = {};
    struct iovec local  = { &bwr, sizeof(bwr) };
    struct iovec remote = { (void *)(uintptr_t)notif->data.args[2], sizeof(bwr) };
    if (process_vm_readv((pid_t)notif->pid, &local, 1, &remote, 1, 0) != sizeof(bwr))
        return;
    if (bwr.write_size < sizeof(uint32_t) + sizeof(struct binder_transaction_data))
        return;

    uint32_t bcmd = 0;
    struct binder_transaction_data txn = {};
    struct iovec li2 = { &bcmd, sizeof(bcmd) };
    struct iovec ri2 = { (void *)(uintptr_t)bwr.write_buffer, sizeof(bcmd) };
    if (process_vm_readv((pid_t)notif->pid, &li2, 1, &ri2, 1, 0) != sizeof(bcmd))
        return;
    if (bcmd != BC_TRANSACTION && bcmd != BC_REPLY)
        return;

    struct iovec li3 = { &txn, sizeof(txn) };
    struct iovec ri3 = { (void *)((uintptr_t)bwr.write_buffer + sizeof(bcmd)), sizeof(txn) };
    if (process_vm_readv((pid_t)notif->pid, &li3, 1, &ri3, 1, 0) != sizeof(txn))
        return;

    pending->txn.code = txn.code;
    pending->txn.target_handle = txn.target.handle;
    // read parcel: txn.data.ptr.buffer, up to PARCEL_CAPTURE_SIZE bytes
}
```

**Risk**: `process_vm_readv()` internally calls `ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS)`. The loader runs as root (uid=0). On Android, `ptrace_may_access` for uid=0 to any app is permitted at the kernel level, but SELinux may deny it via the `ptrace` permission in the loader's domain policy. On a `userdebug` build (which this device is, since we can adb shell as root), the loader's SELinux domain is likely `u:r:su:s0` or `u:r:shell:s0`, which typically has broader ptrace grants.

**Quick verification**: add a single `process_vm_readv` call in the notification handler, log the return value and errno. If it returns the right size, we're done with BPF enrichment.

---

### Summary

- `raw_syscalls/sys_enter` non-firing: by design, seccomp runs first and blocks before the tracepoint.
- `__seccomp_filter` x1=NULL: `__secure_computing(NULL)` passes NULL; sd is populated on-stack after entry.
- No good in-kallsyms hook exists for the seccomp_data at the point where it's populated.
- **Recommended path**: `process_vm_readv()` in the loader, using `notif->data.args[2]` as the `binder_write_read *`. No BPF changes needed. The BPF kprobe can be removed or kept as a no-op for now.

---

## Claude → Codex (turn 4) — implementation brief

**Clarification on `do_seccomp`**: do not hook it. `do_seccomp` is the `seccomp(2)` syscall handler — it runs once when a process *installs* a filter (`seccomp(SECCOMP_SET_MODE_FILTER, ...)`). It is never called during filter evaluation. It tells you nothing about intercepted syscalls.

**Why `__secure_computing` is the right evaluation-time hook**: it runs at every syscall that has a seccomp filter attached. It is the evaluation entry point. It fires in the child's task context with user mm live. It is exported (present in kallsyms). Problem: it is called as `__secure_computing(NULL)` — the `seccomp_data *` argument is NULL at entry; syscall args are only populated on-stack inside `__seccomp_filter` *after* entry. So reading sd from registers does not work.

**Recommended implementation: `process_vm_readv()` in the loader**

This requires no BPF changes. The loader already has everything it needs from `SECCOMP_IOCTL_NOTIF_RECV`:

```c
struct seccomp_notif {
    __u64 id;
    __u32 pid;       // TID of the blocked thread
    __u32 flags;
    struct seccomp_data data;   // .args[1] = ioctl cmd, .args[2] = binder_write_read *
};
```

The child is suspended in-kernel. `notif->data.args[2]` is the live userspace pointer to `binder_write_read`. The loader runs as root. Read the parcel directly:

```c
#include <sys/uio.h>
#include <linux/android/binder.h>   // or local binder_uapi_min.h

static void enrich_from_process_vm(struct proxy_pending_request *pending,
                                   const struct seccomp_notif *notif)
{
    if ((uint32_t)notif->data.args[1] != BINDER_WRITE_READ)
        return;

    // Step 1: read binder_write_read
    struct binder_write_read bwr = {};
    struct iovec lv1 = { &bwr, sizeof(bwr) };
    struct iovec rv1 = { (void *)(uintptr_t)notif->data.args[2], sizeof(bwr) };
    if (process_vm_readv((pid_t)notif->pid, &lv1, 1, &rv1, 1, 0) != (ssize_t)sizeof(bwr))
        return;
    if (bwr.write_size < sizeof(uint32_t) + sizeof(struct binder_transaction_data))
        return;

    // Step 2: read BC_TRANSACTION command word
    uint32_t bcmd = 0;
    struct iovec lv2 = { &bcmd, sizeof(bcmd) };
    struct iovec rv2 = { (void *)(uintptr_t)bwr.write_buffer, sizeof(bcmd) };
    if (process_vm_readv((pid_t)notif->pid, &lv2, 1, &rv2, 1, 0) != (ssize_t)sizeof(bcmd))
        return;
    if (bcmd != BC_TRANSACTION && bcmd != BC_REPLY)
        return;

    // Step 3: read binder_transaction_data
    struct binder_transaction_data txn = {};
    struct iovec lv3 = { &txn, sizeof(txn) };
    struct iovec rv3 = { (void *)((uintptr_t)bwr.write_buffer + sizeof(bcmd)), sizeof(txn) };
    if (process_vm_readv((pid_t)notif->pid, &lv3, 1, &rv3, 1, 0) != (ssize_t)sizeof(txn))
        return;

    pending->txn.code          = txn.code;
    pending->txn.target_handle = txn.target.handle;
    pending->txn.flags         = txn.flags;
    pending->txn.data_size     = (uint32_t)txn.data_size;

    // Step 4: read raw parcel (up to PARCEL_CAPTURE_SIZE bytes)
    uint32_t capture = (uint32_t)txn.data_size;
    if (capture > PARCEL_CAPTURE_SIZE)
        capture = PARCEL_CAPTURE_SIZE;
    if (capture > 0 && txn.data.ptr.buffer != 0) {
        struct iovec lv4 = { pending->txn.raw_parcel, capture };
        struct iovec rv4 = { (void *)(uintptr_t)txn.data.ptr.buffer, capture };
        if (process_vm_readv((pid_t)notif->pid, &lv4, 1, &rv4, 1, 0) == (ssize_t)capture)
            pending->txn.parcel_captured = capture;
    }
}
```

Call `enrich_from_process_vm(&session->pending, &notif)` in `fill_pending_request()` right after the txn_map lookup (as a fallback when iface is empty, or unconditionally).

**SELinux risk**: `process_vm_readv()` calls `ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS)` internally. On a userdebug build with the loader running as root/shell, this should be permitted. Verify by logging the return value and errno on first call. If it returns -1 with EPERM, SELinux is blocking it — in that case fall back to `pread()` on `/proc/<pid>/mem` (same permission model, different syscall).

**What to keep from the BPF work**: the kprobe on `__seccomp_filter` can be removed or left as a no-op. The txn_map and BPF maps infrastructure can be removed if `process_vm_readv` works — the loader already has everything from the seccomp notification.

---
