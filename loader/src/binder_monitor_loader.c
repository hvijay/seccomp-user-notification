#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/seccomp.h>
#include <linux/types.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/uio.h>
#include <unistd.h>

#include "../compat/libbpf_min.h"
#include "../compat/binder_uapi_min.h"
#include "shared_types.h"

/* Strip ARM64 MTE tag bits before passing a user pointer to process_vm_readv. */
static inline uintptr_t untag_uptr(uint64_t ptr)
{
    return (uintptr_t)(ptr & 0x00FFFFFFFFFFFFFFULL);
}

#define DEFAULT_BPF_OBJ "/data/local/tmp/binder_monitor.bpf.o"
#define DEFAULT_PIN_DIR "/sys/fs/bpf/binder_monitor"
#define DEFAULT_LINK_PATH DEFAULT_PIN_DIR "/link"
#define DEFAULT_TXN_MAP_PATH DEFAULT_PIN_DIR "/txn_map"
#define DEFAULT_DEBUG_COUNTERS_PATH DEFAULT_PIN_DIR "/debug_counters"
#define DEFAULT_PROXY_SOCKET_PATH "@binder_monitor_proxy"

struct options {
    bool unload_only;
    bool serve;
    bool daemon_mode; /* serve without a target pid; cgroup filter disabled */
    pid_t target_pid;
    const char* bpf_obj_path;
    const char* pin_dir;
    const char* link_path;
    const char* txn_map_path;
    const char* proxy_socket_path;
};

static void usage(FILE* stream, const char* argv0)
{
    fprintf(stream,
            "Usage:\n"
            "  %s load --pid <target-pid> [--obj <path>] [--pin-dir <dir>] [--link <path>] [--txn-map <path>]\n"
            "  %s serve --pid <target-pid> [--obj <path>] [--pin-dir <dir>] [--link <path>] [--txn-map <path>] [--proxy-socket <path>]\n"
            "  %s daemon [--obj <path>] [--pin-dir <dir>] [--link <path>] [--txn-map <path>] [--proxy-socket <path>]\n"
            "  %s unload [--pin-dir <dir>] [--link <path>] [--txn-map <path>]\n",
            argv0, argv0, argv0, argv0);
}

static int libbpf_logger(int level, const char* format, va_list args)
{
    (void)level;
    return vfprintf(stderr, format, args);
}

static int mkdir_p(const char* path)
{
    char tmp[PATH_MAX];
    size_t len;

    if (!path || !path[0]) {
        errno = EINVAL;
        return -1;
    }

    len = strnlen(path, sizeof(tmp));
    if (len == 0 || len >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    memcpy(tmp, path, len + 1);
    for (char* p = tmp + 1; *p; ++p) {
        if (*p != '/') {
            continue;
        }
        *p = '\0';
        if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
            return -1;
        }
        *p = '/';
    }

    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

static int chmod_if_exists(const char* path, mode_t mode)
{
    if (chmod(path, mode) == 0 || errno == ENOENT) {
        return 0;
    }
    return -1;
}

static int unlink_if_exists(const char* path)
{
    if (unlink(path) == 0 || errno == ENOENT) {
        return 0;
    }
    return -1;
}

static bool is_abstract_socket_name(const char* path)
{
    return path != NULL && path[0] == '@' && path[1] != '\0';
}

static socklen_t make_sockaddr_un(const char* path, struct sockaddr_un* addr)
{
    size_t name_len;

    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;

    if (is_abstract_socket_name(path)) {
        name_len = strnlen(path + 1, sizeof(addr->sun_path) - 1);
        memcpy(addr->sun_path + 1, path + 1, name_len);
        return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + name_len);
    }

    strncpy(addr->sun_path, path, sizeof(addr->sun_path) - 1);
    return sizeof(*addr);
}

static int read_cgroup_path_for_pid(pid_t pid, char* out, size_t out_size)
{
    char proc_path[64];
    FILE* input;
    char line[PATH_MAX];

    snprintf(proc_path, sizeof(proc_path), "/proc/%d/cgroup", pid);
    input = fopen(proc_path, "re");
    if (!input) {
        return -1;
    }

    while (fgets(line, sizeof(line), input)) {
        const char prefix[] = "0::";
        size_t line_len;

        if (strncmp(line, prefix, sizeof(prefix) - 1) != 0) {
            continue;
        }

        line_len = strcspn(line, "\r\n");
        line[line_len] = '\0';
        if (snprintf(out, out_size, "/sys/fs/cgroup%s", line + (sizeof(prefix) - 1)) >=
            (int)out_size) {
            fclose(input);
            errno = ENAMETOOLONG;
            return -1;
        }
        fclose(input);
        return 0;
    }

    fclose(input);
    errno = ENOENT;
    return -1;
}

static int parse_args(int argc, char** argv, struct options* options)
{
    memset(options, 0, sizeof(*options));
    options->bpf_obj_path = DEFAULT_BPF_OBJ;
    options->pin_dir = DEFAULT_PIN_DIR;
    options->link_path = DEFAULT_LINK_PATH;
    options->txn_map_path = DEFAULT_TXN_MAP_PATH;
    options->proxy_socket_path = DEFAULT_PROXY_SOCKET_PATH;

    if (argc < 2) {
        return -1;
    }

    if (strcmp(argv[1], "load") == 0) {
        options->unload_only = false;
        options->serve = false;
        options->daemon_mode = false;
    } else if (strcmp(argv[1], "serve") == 0) {
        options->unload_only = false;
        options->serve = true;
        options->daemon_mode = false;
    } else if (strcmp(argv[1], "daemon") == 0) {
        options->unload_only = false;
        options->serve = true;
        options->daemon_mode = true;
    } else if (strcmp(argv[1], "unload") == 0) {
        options->unload_only = true;
    } else {
        return -1;
    }

    for (int i = 2; i < argc; ++i) {
        const char* arg = argv[i];
        if (strcmp(arg, "--pid") == 0 && i + 1 < argc) {
            options->target_pid = (pid_t)strtol(argv[++i], NULL, 10);
        } else if (strcmp(arg, "--obj") == 0 && i + 1 < argc) {
            options->bpf_obj_path = argv[++i];
        } else if (strcmp(arg, "--pin-dir") == 0 && i + 1 < argc) {
            options->pin_dir = argv[++i];
        } else if (strcmp(arg, "--link") == 0 && i + 1 < argc) {
            options->link_path = argv[++i];
        } else if (strcmp(arg, "--txn-map") == 0 && i + 1 < argc) {
            options->txn_map_path = argv[++i];
        } else if (strcmp(arg, "--proxy-socket") == 0 && i + 1 < argc) {
            options->proxy_socket_path = argv[++i];
        } else {
            return -1;
        }
    }

    if (!options->unload_only && !options->daemon_mode && options->target_pid <= 0) {
        return -1;
    }

    return 0;
}

static int sys_bpf(enum bpf_cmd cmd, union bpf_attr* attr)
{
    return (int)syscall(SYS_bpf, cmd, attr, sizeof(*attr));
}

enum {
    BPF_MAP_UPDATE_ELEM_CMD = 2,
    BPF_MAP_LOOKUP_AND_DELETE_ELEM_CMD = 21,
};

struct bpf_attr_map_elem {
    uint32_t map_fd;
    uint32_t pad;
    uint64_t key;
    uint64_t value;
    uint64_t flags;
};

static int sys_bpf_map_update_elem(int map_fd, const void* key, const void* value, uint64_t flags)
{
    struct bpf_attr_map_elem attr = {
        .map_fd = (uint32_t)map_fd,
        .key = (uint64_t)(uintptr_t)key,
        .value = (uint64_t)(uintptr_t)value,
        .flags = flags,
    };

    return (int)syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM_CMD, &attr, sizeof(attr));
}

static int sys_bpf_map_lookup_and_delete_elem(int map_fd, const void* key, void* value)
{
    struct bpf_attr_map_elem attr = {
        .map_fd = (uint32_t)map_fd,
        .key = (uint64_t)(uintptr_t)key,
        .value = (uint64_t)(uintptr_t)value,
        .flags = 0,
    };

    return (int)syscall(SYS_bpf, BPF_MAP_LOOKUP_AND_DELETE_ELEM_CMD, &attr, sizeof(attr));
}

static ssize_t write_full(int fd, const void* buf, size_t n)
{
    size_t written = 0;
    while (written < n) {
        ssize_t r = write(fd, (const char*)buf + written, n - written);
        if (r <= 0) {
            return r == 0 ? (ssize_t)written : r;
        }
        written += (size_t)r;
    }
    return (ssize_t)written;
}

static ssize_t read_full(int fd, void* buf, size_t n)
{
    size_t total = 0;
    while (total < n) {
        ssize_t r = read(fd, (char*)buf + total, n - total);
        if (r <= 0) {
            return r == 0 ? (ssize_t)total : r;
        }
        total += (size_t)r;
    }
    return (ssize_t)total;
}

struct active_session {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int listener_fd;
    int txn_map_fd;
    bool worker_running;
    bool stop_worker;
    bool has_pending;
    bool decision_ready;
    bool allow;
    struct seccomp_notif current_notif;
    struct proxy_pending_request pending;
    pthread_t worker_thread;
};

struct proxy_client_args {
    int client_fd;
    int txn_map_fd;
    int target_map_fd;
    uint32_t target_pid;
    struct active_session session;
};

static int recv_fd_with_status(int sock_fd, int* out_fd)
{
    struct msghdr msg;
    struct iovec iov;
    int status = -EIO;
    char control[CMSG_SPACE(sizeof(int))];

    memset(&msg, 0, sizeof(msg));
    memset(control, 0, sizeof(control));
    iov.iov_base = &status;
    iov.iov_len = sizeof(status);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    if (recvmsg(sock_fd, &msg, 0) != (ssize_t)sizeof(status)) {
        return -1;
    }

    *out_fd = -1;
    for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
         cmsg != NULL;
         cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET &&
            cmsg->cmsg_type == SCM_RIGHTS &&
            cmsg->cmsg_len >= CMSG_LEN(sizeof(int))) {
            memcpy(out_fd, CMSG_DATA(cmsg), sizeof(int));
            break;
        }
    }
    return status;
}

static void enrich_from_process_vm(struct binder_txn_info* txn,
                                   const struct seccomp_notif* notif)
{
    if ((uint32_t)notif->data.args[1] != (uint32_t)BINDER_WRITE_READ)
        return;

    struct binder_write_read bwr = {};
    struct iovec lv1 = { &bwr, sizeof(bwr) };
    struct iovec rv1 = { (void *)untag_uptr(notif->data.args[2]), sizeof(bwr) };
    if (process_vm_readv((pid_t)notif->pid, &lv1, 1, &rv1, 1, 0) != (ssize_t)sizeof(bwr)) {
        fprintf(stderr, "proxy: process_vm_readv bwr failed pid=%u: %s\n",
                notif->pid, strerror(errno));
        return;
    }

    if (bwr.write_size < sizeof(uint32_t) + sizeof(struct binder_transaction_data))
        return;

    uint32_t bcmd = 0;
    struct iovec lv2 = { &bcmd, sizeof(bcmd) };
    struct iovec rv2 = { (void *)untag_uptr(bwr.write_buffer), sizeof(bcmd) };
    if (process_vm_readv((pid_t)notif->pid, &lv2, 1, &rv2, 1, 0) != (ssize_t)sizeof(bcmd))
        return;

    if (bcmd != (uint32_t)BC_TRANSACTION && bcmd != (uint32_t)BC_REPLY)
        return;

    struct binder_transaction_data txn_data = {};
    struct iovec lv3 = { &txn_data, sizeof(txn_data) };
    struct iovec rv3 = { (void *)(untag_uptr(bwr.write_buffer) + sizeof(bcmd)), sizeof(txn_data) };
    if (process_vm_readv((pid_t)notif->pid, &lv3, 1, &rv3, 1, 0) != (ssize_t)sizeof(txn_data))
        return;

    txn->target_handle = txn_data.target.handle;
    txn->code          = txn_data.code;
    txn->flags         = txn_data.flags;
    txn->data_size     = (uint32_t)txn_data.data_size;
    txn->offsets_size  = (uint32_t)txn_data.offsets_size;
    txn->is_reply      = (bcmd == (uint32_t)BC_REPLY) ? 1 : 0;
    txn->parcel_truncated = txn_data.data_size > PARCEL_CAPTURE_SIZE ? 1 : 0;

    uint32_t capture = (uint32_t)txn_data.data_size;
    if (capture > PARCEL_CAPTURE_SIZE)
        capture = PARCEL_CAPTURE_SIZE;

    if (capture > 0 && txn_data.data.ptr.buffer != 0) {
        struct iovec lv4 = { txn->raw_parcel, capture };
        struct iovec rv4 = { (void *)untag_uptr(txn_data.data.ptr.buffer), capture };
        if (process_vm_readv((pid_t)notif->pid, &lv4, 1, &rv4, 1, 0) == (ssize_t)capture) {
            txn->parcel_captured = capture;
            fprintf(stdout, "proxy: process_vm_readv parcel ok pid=%u code=%u handle=%u"
                    " data_size=%u captured=%u\n",
                    notif->pid, txn->code, txn->target_handle,
                    txn->data_size, capture);
        }
    }
}

static void enrich_open_from_process_vm(struct proxy_pending_request* pending,
                                        const struct seccomp_notif* notif)
{
    if ((uint32_t)notif->data.nr != __NR_openat) {
        return;
    }

    pending->operation_kind = OP_KIND_FILE_OPEN;
    pending->open_flags = (uint32_t)notif->data.args[2];
    pending->open_mode = (uint32_t)notif->data.args[3];

    memset(pending->file_path, 0, sizeof(pending->file_path));
    struct iovec local = { pending->file_path, sizeof(pending->file_path) - 1 };
    struct iovec remote = { (void *)untag_uptr(notif->data.args[1]), sizeof(pending->file_path) - 1 };
    ssize_t n = process_vm_readv((pid_t)notif->pid, &local, 1, &remote, 1, 0);
    if (n < 0) {
        fprintf(stderr, "proxy: process_vm_readv file path failed pid=%u: %s\n",
                notif->pid, strerror(errno));
        pending->file_path[0] = '\0';
        return;
    }
    pending->file_path[sizeof(pending->file_path) - 1] = '\0';
}

static bool read_remote_cstring(pid_t pid, uint64_t remote_ptr, char* out, size_t out_size)
{
    if (out_size == 0) {
        return false;
    }
    memset(out, 0, out_size);
    if (remote_ptr == 0) {
        return false;
    }

    struct iovec local = { out, out_size - 1 };
    struct iovec remote = { (void*)untag_uptr(remote_ptr), out_size - 1 };
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (n < 0) {
        return false;
    }
    out[out_size - 1] = '\0';
    return true;
}

static void enrich_exec_from_process_vm(struct proxy_pending_request* pending,
                                        const struct seccomp_notif* notif)
{
    if ((uint32_t)notif->data.nr != __NR_execve) {
        return;
    }

    pending->operation_kind = OP_KIND_EXEC;
    memset(pending->file_path, 0, sizeof(pending->file_path));
    memset(pending->exec_argv, 0, sizeof(pending->exec_argv));

    read_remote_cstring((pid_t)notif->pid, notif->data.args[0], pending->file_path,
                        sizeof(pending->file_path));

    uintptr_t argv_ptr = untag_uptr(notif->data.args[1]);
    if (argv_ptr == 0) {
        return;
    }

    size_t used = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t arg_ptr = 0;
        struct iovec local = { &arg_ptr, sizeof(arg_ptr) };
        struct iovec remote = { (void*)(argv_ptr + (i * sizeof(uint64_t))), sizeof(arg_ptr) };
        if (process_vm_readv((pid_t)notif->pid, &local, 1, &remote, 1, 0) !=
            (ssize_t)sizeof(arg_ptr)) {
            break;
        }
        if (arg_ptr == 0) {
            break;
        }

        char arg[128];
        if (!read_remote_cstring((pid_t)notif->pid, arg_ptr, arg, sizeof(arg))) {
            break;
        }

        int n = snprintf(pending->exec_argv + used,
                         sizeof(pending->exec_argv) - used,
                         "%s\"%s\"",
                         used == 0 ? "" : ", ",
                         arg);
        if (n < 0 || (size_t)n >= sizeof(pending->exec_argv) - used) {
            used = sizeof(pending->exec_argv) - 1;
            break;
        }
        used += (size_t)n;
    }
}

static void fill_pending_request(struct proxy_pending_request* pending,
                                 const struct seccomp_notif* notif,
                                 int txn_map_fd)
{
    memset(pending, 0, sizeof(*pending));
    pending->notification_id = notif->id;
    pending->pid = notif->pid;
    pending->syscall_nr = notif->data.nr;
    pending->ioctl_cmd = notif->data.args[1];

    if ((uint32_t)notif->data.nr == __NR_openat) {
        enrich_open_from_process_vm(pending, notif);
        return;
    }
    if ((uint32_t)notif->data.nr == __NR_execve) {
        enrich_exec_from_process_vm(pending, notif);
        return;
    }

    pending->operation_kind = OP_KIND_BINDER;

    if (txn_map_fd >= 0 &&
        sys_bpf_map_lookup_and_delete_elem(txn_map_fd, &pending->pid, &pending->txn) != 0 &&
        errno != ENOENT) {
        fprintf(stderr, "proxy: lookup tid=%u failed: %s\n",
                pending->pid, strerror(errno));
    }

    /* Fall back to process_vm_readv when the BPF side did not capture the raw parcel. */
    if (pending->txn.parcel_captured == 0)
        enrich_from_process_vm(&pending->txn, notif);
}

static void* active_session_thread(void* opaque)
{
    struct active_session* session = (struct active_session*)opaque;
    fprintf(stdout, "proxy: worker started listener_fd=%d txn_map_fd=%d\n",
            session->listener_fd, session->txn_map_fd);
    fflush(stdout);
    for (;;) {
        pthread_mutex_lock(&session->mutex);
        if (session->stop_worker) {
            pthread_mutex_unlock(&session->mutex);
            break;
        }
        pthread_mutex_unlock(&session->mutex);

        struct seccomp_notif notif;
        memset(&notif, 0, sizeof(notif));
        fprintf(stdout, "proxy: waiting for seccomp notification fd=%d\n", session->listener_fd);
        fflush(stdout);
        if (ioctl(session->listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &notif) != 0) {
            if (!session->stop_worker) {
                fprintf(stderr, "proxy: SECCOMP_IOCTL_NOTIF_RECV failed: %s\n", strerror(errno));
            }
            break;
        }
        fprintf(stdout,
                "proxy: received seccomp notification id=%llu pid=%u nr=%d arg1=%llu\n",
                (unsigned long long)notif.id,
                notif.pid,
                notif.data.nr,
                (unsigned long long)notif.data.args[1]);
        fflush(stdout);

        pthread_mutex_lock(&session->mutex);
        if (session->stop_worker) {
            pthread_mutex_unlock(&session->mutex);
            break;
        }

        memset(&session->current_notif, 0, sizeof(session->current_notif));
        session->current_notif = notif;
        fill_pending_request(&session->pending, &notif, session->txn_map_fd);
        if (session->pending.operation_kind == OP_KIND_FILE_OPEN) {
            fprintf(stdout,
                    "proxy: pending file-open id=%llu tid=%u path=%s flags=0x%x\n",
                    (unsigned long long)session->pending.notification_id,
                    session->pending.pid,
                    session->pending.file_path,
                    session->pending.open_flags);
        } else if (session->pending.operation_kind == OP_KIND_EXEC) {
            fprintf(stdout,
                    "proxy: pending exec id=%llu tid=%u path=%s argv=[%s]\n",
                    (unsigned long long)session->pending.notification_id,
                    session->pending.pid,
                    session->pending.file_path,
                    session->pending.exec_argv);
        } else {
            fprintf(stdout,
                    "proxy: pending binder id=%llu tid=%u code=%u handle=%u captured=%u\n",
                    (unsigned long long)session->pending.notification_id,
                    session->pending.pid,
                    session->pending.txn.code,
                    session->pending.txn.target_handle,
                    session->pending.txn.parcel_captured);
        }
        fflush(stdout);
        session->has_pending = true;
        session->decision_ready = false;
        pthread_cond_broadcast(&session->cond);

        while (!session->decision_ready && !session->stop_worker) {
            pthread_cond_wait(&session->cond, &session->mutex);
        }

        bool allow = true;
        if (session->decision_ready) {
            allow = session->allow;
        }
        session->has_pending = false;
        session->decision_ready = false;
        pthread_cond_broadcast(&session->cond);
        pthread_mutex_unlock(&session->mutex);

        struct seccomp_notif_resp response;
        memset(&response, 0, sizeof(response));
        response.id = notif.id;
        response.val = allow ? 0 : -1;
        response.error = allow ? 0 : -EPERM;
        response.flags = allow ? SECCOMP_USER_NOTIF_FLAG_CONTINUE : 0;
        fprintf(stdout,
                "proxy: sending seccomp response id=%llu allow=%d\n",
                (unsigned long long)notif.id,
                allow ? 1 : 0);
        fflush(stdout);
        if (ioctl(session->listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &response) != 0) {
            fprintf(stderr, "proxy: SECCOMP_IOCTL_NOTIF_SEND failed id=%llu: %s\n",
                    (unsigned long long)notif.id, strerror(errno));
        }

        pthread_mutex_lock(&session->mutex);
        if (session->stop_worker) {
            pthread_mutex_unlock(&session->mutex);
            break;
        }
        pthread_mutex_unlock(&session->mutex);
    }

    pthread_mutex_lock(&session->mutex);
    session->worker_running = false;
    session->has_pending = false;
    session->decision_ready = false;
    if (session->listener_fd >= 0) {
        close(session->listener_fd);
        session->listener_fd = -1;
    }
    pthread_cond_broadcast(&session->cond);
    pthread_mutex_unlock(&session->mutex);
    fprintf(stdout, "proxy: worker exiting\n");
    fflush(stdout);
    return NULL;
}

static void stop_active_session(struct active_session* session)
{
    pthread_mutex_lock(&session->mutex);
    int listener_fd = session->listener_fd;
    bool worker_running = session->worker_running;
    bool has_pending = session->has_pending;
    session->stop_worker = true;
    session->allow = true;
    session->decision_ready = true;
    pthread_cond_broadcast(&session->cond);
    if (!has_pending && listener_fd >= 0) {
        close(listener_fd);
        session->listener_fd = -1;
    }
    pthread_mutex_unlock(&session->mutex);

    if (worker_running) {
        pthread_join(session->worker_thread, NULL);
    }

    pthread_mutex_lock(&session->mutex);
    session->stop_worker = false;
    session->has_pending = false;
    session->decision_ready = false;
    memset(&session->pending, 0, sizeof(session->pending));
    memset(&session->current_notif, 0, sizeof(session->current_notif));
    pthread_mutex_unlock(&session->mutex);
}

static int start_active_session(struct active_session* session, int listener_fd, int txn_map_fd)
{
    stop_active_session(session);

    pthread_mutex_lock(&session->mutex);
    session->listener_fd = listener_fd;
    session->txn_map_fd = txn_map_fd;
    session->stop_worker = false;
    session->has_pending = false;
    session->decision_ready = false;
    if (pthread_create(&session->worker_thread, NULL, active_session_thread, session) != 0) {
        int saved = errno;
        close(listener_fd);
        session->listener_fd = -1;
        pthread_mutex_unlock(&session->mutex);
        errno = saved;
        return -1;
    }
    session->worker_running = true;
    pthread_mutex_unlock(&session->mutex);
    return 0;
}

static int update_target_map_for_pid(int target_map_fd, uint32_t pid)
{
    uint64_t target_pid = 0;
    uint32_t zero = 0;
    if (pid == 0) {
        if (sys_bpf_map_update_elem(target_map_fd, &zero, &target_pid, 0) != 0) {
            fprintf(stderr, "proxy: SET_TARGET clear failed: %s\n", strerror(errno));
            return -1;
        }
        fprintf(stdout, "proxy: monitoring disabled\n");
        fflush(stdout);
        return 0;
    }

    target_pid = pid;
    if (sys_bpf_map_update_elem(target_map_fd, &zero, &target_pid, 0) != 0) {
        fprintf(stderr, "proxy: SET_TARGET pid map update failed: %s\n", strerror(errno));
        return -1;
    }

    fprintf(stdout, "proxy: monitoring pid=%u\n", pid);
    fflush(stdout);
    return 0;
}

static void handle_proxy_client(struct proxy_client_args* args)
{
    struct active_session* session = &args->session;
    int client_fd = args->client_fd;
    uint8_t msg_type;
    while (read_full(client_fd, &msg_type, 1) == 1) {
        if (msg_type == PROXY_MSG_SET_TARGET) {
            uint32_t pid = 0;
            if (read_full(client_fd, &pid, sizeof(pid)) != (ssize_t)sizeof(pid)) {
                break;
            }
            uint8_t ok = 1;
            if (update_target_map_for_pid(args->target_map_fd, pid) != 0) {
                ok = 0;
            } else {
                args->target_pid = pid;
            }
            if (write_full(client_fd, &ok, 1) != 1) {
                break;
            }
        } else if (msg_type == PROXY_MSG_REGISTER_LISTENER) {
            int listener_fd = -1;
            int status = recv_fd_with_status(client_fd, &listener_fd);
            uint8_t ok = 1;
            if (status != 0 || listener_fd < 0) {
                fprintf(stderr, "proxy: register listener recv failed status=%d fd=%d\n", status, listener_fd);
                ok = 0;
            } else if (start_active_session(session, listener_fd, args->txn_map_fd) != 0) {
                fprintf(stderr, "proxy: register listener failed: %s\n", strerror(errno));
                ok = 0;
            } else {
                fprintf(stdout, "proxy: listener registered fd=%d\n", listener_fd);
                fflush(stdout);
            }
            if (write_full(client_fd, &ok, 1) != 1) {
                break;
            }
        } else if (msg_type == PROXY_MSG_GET_PENDING) {
            uint8_t found = 0;
            struct proxy_pending_request pending;
            memset(&pending, 0, sizeof(pending));
            pthread_mutex_lock(&session->mutex);
            if (session->has_pending) {
                found = 1;
                pending = session->pending;
            }
            pthread_mutex_unlock(&session->mutex);
            fprintf(stdout,
                    "proxy: GET_PENDING found=%u notification_id=%llu tid=%u\n",
                    found,
                    (unsigned long long)pending.notification_id,
                    pending.pid);
            fflush(stdout);
            if (write_full(client_fd, &found, 1) != 1) {
                break;
            }
            if (write_full(client_fd, &pending, sizeof(pending)) != (ssize_t)sizeof(pending)) {
                break;
            }
        } else if (msg_type == PROXY_MSG_SEND_DECISION) {
            uint64_t notification_id = 0;
            int32_t allow = 0;
            uint8_t ok = 1;
            if (read_full(client_fd, &notification_id, sizeof(notification_id)) != (ssize_t)sizeof(notification_id) ||
                read_full(client_fd, &allow, sizeof(allow)) != (ssize_t)sizeof(allow)) {
                break;
            }
            pthread_mutex_lock(&session->mutex);
            if (!session->has_pending ||
                session->pending.notification_id != notification_id) {
                ok = 0;
            } else {
                session->allow = allow != 0;
                session->decision_ready = true;
                pthread_cond_broadcast(&session->cond);
            }
            pthread_mutex_unlock(&session->mutex);
            fprintf(stdout,
                    "proxy: SEND_DECISION id=%llu allow=%d ok=%u\n",
                    (unsigned long long)notification_id,
                    allow,
                    ok);
            fflush(stdout);
            if (write_full(client_fd, &ok, 1) != 1) {
                break;
            }
        } else if (msg_type == PROXY_MSG_UNREGISTER) {
            uint8_t ok = 1;
            stop_active_session(session);
            if (write_full(client_fd, &ok, 1) != 1) {
                break;
            }
        } else if (msg_type == PROXY_MSG_LOOKUP_TID) {
            uint32_t tid = 0;
            if (read_full(client_fd, &tid, sizeof(tid)) != (ssize_t)sizeof(tid)) {
                break;
            }
            uint8_t found = 0;
            struct binder_txn_info info;
            memset(&info, 0, sizeof(info));
            if (sys_bpf_map_lookup_and_delete_elem(args->txn_map_fd, &tid, &info) == 0) {
                found = 1;
            } else if (errno != ENOENT) {
                fprintf(stderr, "proxy: lookup tid=%u: %s\n", tid, strerror(errno));
            }
            if (write_full(client_fd, &found, 1) != 1) {
                break;
            }
            if (write_full(client_fd, &info, sizeof(info)) != (ssize_t)sizeof(info)) {
                break;
            }
        } else {
            fprintf(stderr, "proxy: unknown msg_type=0x%02x, closing connection\n", msg_type);
            break;
        }
    }
}

static void* handle_proxy_client_thread(void* opaque)
{
    struct proxy_client_args* args = (struct proxy_client_args*)opaque;
    handle_proxy_client(args);
    stop_active_session(&args->session);
    if (args->target_pid != 0) {
        update_target_map_for_pid(args->target_map_fd, 0);
    }
    pthread_mutex_destroy(&args->session.mutex);
    pthread_cond_destroy(&args->session.cond);
    close(args->client_fd);
    free(args);
    return NULL;
}

static int unload_pins(const struct options* options)
{
    char target_map_path[PATH_MAX];
    char debug_counters_path[PATH_MAX];
    snprintf(target_map_path, sizeof(target_map_path), "%s/target_cgroup_map", options->pin_dir);
    snprintf(debug_counters_path, sizeof(debug_counters_path), "%s/debug_counters", options->pin_dir);

    int status = 0;

    if (unlink_if_exists(options->link_path) != 0) {
        fprintf(stderr, "failed to remove pinned link %s: %s\n",
                options->link_path, strerror(errno));
        status = 1;
    }
    if (unlink_if_exists(options->txn_map_path) != 0) {
        fprintf(stderr, "failed to remove pinned map %s: %s\n",
                options->txn_map_path, strerror(errno));
        status = 1;
    }
    if (unlink_if_exists(target_map_path) != 0) {
        fprintf(stderr, "failed to remove pinned map %s: %s\n",
                target_map_path, strerror(errno));
        status = 1;
    }
    if (unlink_if_exists(debug_counters_path) != 0) {
        fprintf(stderr, "failed to remove pinned map %s: %s\n",
                debug_counters_path, strerror(errno));
        status = 1;
    }
    if (rmdir(options->pin_dir) != 0 && errno != ENOENT && errno != ENOTEMPTY) {
        fprintf(stderr, "failed to remove pin dir %s: %s\n",
                options->pin_dir, strerror(errno));
        status = 1;
    }
    return status;
}

static int do_load(const struct options* options)
{
    struct bpf_object* obj = NULL;
    struct bpf_program* prog;
    struct bpf_link* link = NULL;
    uint32_t zero = 0;
    uint64_t target_pid = 0;
    int target_map_fd = -1;
    int txn_map_fd = -1;
    int status = 1;

    if (options->target_pid > 0) {
        target_pid = (uint64_t)options->target_pid;
    } else {
        /* daemon mode: start with pid=0 (disabled); policydaemon will SET_TARGET later */
        target_pid = 0;
    }

    if (mkdir_p(options->pin_dir) != 0) {
        fprintf(stderr, "failed to create pin dir %s: %s\n",
                options->pin_dir, strerror(errno));
        goto out;
    }
    if (chmod_if_exists("/sys/fs/bpf", 0755) != 0 ||
        chmod_if_exists(options->pin_dir, 0755) != 0) {
        fprintf(stderr, "failed to relax bpffs directory permissions: %s\n", strerror(errno));
        goto out;
    }

    if (unlink_if_exists(options->link_path) != 0) {
        fprintf(stderr, "failed to clear stale link pin %s: %s\n",
                options->link_path, strerror(errno));
        goto out;
    }
    if (unlink_if_exists(options->txn_map_path) != 0) {
        fprintf(stderr, "failed to clear stale map pin %s: %s\n",
                options->txn_map_path, strerror(errno));
        goto out;
    }

    char stale_target_map_path[PATH_MAX];
    char stale_debug_counters_path[PATH_MAX];
    snprintf(stale_target_map_path, sizeof(stale_target_map_path),
             "%s/target_cgroup_map", options->pin_dir);
    if (unlink_if_exists(stale_target_map_path) != 0) {
        fprintf(stderr, "failed to clear stale map pin %s: %s\n",
                stale_target_map_path, strerror(errno));
        goto out;
    }
    snprintf(stale_debug_counters_path, sizeof(stale_debug_counters_path),
             "%s/debug_counters", options->pin_dir);
    if (unlink_if_exists(stale_debug_counters_path) != 0) {
        fprintf(stderr, "failed to clear stale map pin %s: %s\n",
                stale_debug_counters_path, strerror(errno));
        goto out;
    }

    obj = bpf_object__open_file(options->bpf_obj_path, NULL);
    if (!obj || libbpf_get_error(obj)) {
        fprintf(stderr, "failed to open BPF object %s\n", options->bpf_obj_path);
        obj = NULL;
        goto out;
    }

    if (bpf_object__load(obj) != 0) {
        fprintf(stderr, "failed to load BPF object %s\n", options->bpf_obj_path);
        goto out;
    }

    target_map_fd = bpf_object__find_map_fd_by_name(obj, "target_cgroup_map");
    txn_map_fd = bpf_object__find_map_fd_by_name(obj, "txn_map");
    if (target_map_fd < 0 || txn_map_fd < 0) {
        fprintf(stderr, "failed to find required map fds in %s\n", options->bpf_obj_path);
        goto out;
    }
    if (sys_bpf_map_update_elem(target_map_fd, &zero, &target_pid, 0) != 0) {
        fprintf(stderr, "failed to set target pid %llu: %s\n",
                (unsigned long long)target_pid, strerror(errno));
        goto out;
    }

    struct bpf_map* txn_map = bpf_object__find_map_by_name(obj, "txn_map");
    if (!txn_map || bpf_map__pin(txn_map, options->txn_map_path) != 0) {
        fprintf(stderr, "failed to pin txn_map at %s\n", options->txn_map_path);
        goto out;
    }
    if (chmod_if_exists(options->txn_map_path, 0666) != 0) {
        fprintf(stderr, "failed to relax txn_map permissions at %s: %s\n",
                options->txn_map_path, strerror(errno));
        goto out;
    }

    char debug_counters_path[PATH_MAX];
    snprintf(debug_counters_path, sizeof(debug_counters_path),
             "%s/debug_counters", options->pin_dir);
    struct bpf_map* debug_counters = bpf_object__find_map_by_name(obj, "debug_counters");
    if (!debug_counters || bpf_map__pin(debug_counters, debug_counters_path) != 0) {
        fprintf(stderr, "failed to pin debug_counters at %s\n", debug_counters_path);
        goto out;
    }
    if (chmod_if_exists(debug_counters_path, 0666) != 0) {
        fprintf(stderr, "failed to relax debug_counters permissions at %s: %s\n",
                debug_counters_path, strerror(errno));
        goto out;
    }

    /* Pin target_cgroup_map so do_serve can re-open it for dynamic SET_TARGET updates. */
    char target_map_pin_path[PATH_MAX];
    snprintf(target_map_pin_path, sizeof(target_map_pin_path),
             "%s/target_cgroup_map", options->pin_dir);
    struct bpf_map* target_map_obj = bpf_object__find_map_by_name(obj, "target_cgroup_map");
    if (!target_map_obj || bpf_map__pin(target_map_obj, target_map_pin_path) != 0) {
        fprintf(stderr, "failed to pin target_cgroup_map at %s\n", target_map_pin_path);
        goto out;
    }

    prog = bpf_object__find_program_by_name(obj, "binder_monitor");
    if (!prog) {
        fprintf(stderr, "failed to find binder_monitor program\n");
        goto out;
    }

    link = bpf_program__attach_kprobe(prog, false, "do_seccomp");
    if (!link || libbpf_get_error(link)) {
        fprintf(stderr, "failed to attach binder_monitor to kprobe/do_seccomp\n");
        link = NULL;
        goto out;
    }
    if (bpf_link__pin(link, options->link_path) != 0) {
        fprintf(stderr, "failed to pin link at %s\n", options->link_path);
        goto out;
    }

    if (options->target_pid > 0) {
        fprintf(stdout,
                "loaded %s for pid=%d\n"
                "pinned link=%s\n"
                "pinned txn_map=%s\n",
                options->bpf_obj_path,
                options->target_pid,
                options->link_path,
                options->txn_map_path);
    } else {
        fprintf(stdout,
                "loaded %s in daemon mode (idle; send SET_TARGET to begin monitoring)\n"
                "pinned link=%s\n"
                "pinned txn_map=%s\n",
                options->bpf_obj_path,
                options->link_path,
                options->txn_map_path);
    }
    status = 0;

out:
    if (link) {
        bpf_link__destroy(link);
    }
    if (status != 0) {
        unlink_if_exists(options->link_path);
        unlink_if_exists(options->txn_map_path);
        char cleanup_target_path[PATH_MAX];
        char cleanup_debug_counters_path[PATH_MAX];
        snprintf(cleanup_target_path, sizeof(cleanup_target_path),
                 "%s/target_cgroup_map", options->pin_dir);
        unlink_if_exists(cleanup_target_path);
        snprintf(cleanup_debug_counters_path, sizeof(cleanup_debug_counters_path),
                 "%s/debug_counters", options->pin_dir);
        unlink_if_exists(cleanup_debug_counters_path);
    }
    if (obj) {
        bpf_object__close(obj);
    }
    return status;
}

static int open_pinned_map(const char* path)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = (uint64_t)(uintptr_t)path;
    attr.file_flags = 0;
    return sys_bpf(BPF_OBJ_GET, &attr);
}

static int do_serve(const struct options* options)
{
    if (do_load(options) != 0) {
        return 1;
    }

    /* Re-open pinned maps as root so we can operate after bpf_object is closed. */
    int txn_map_fd = open_pinned_map(options->txn_map_path);
    if (txn_map_fd < 0) {
        fprintf(stderr, "serve: BPF_OBJ_GET(%s) failed: %s\n",
                options->txn_map_path, strerror(errno));
        return 1;
    }

    /* Also need the target_cgroup_map for dynamic SET_TARGET updates. */
    char target_map_path[PATH_MAX];
    snprintf(target_map_path, sizeof(target_map_path), "%s/target_cgroup_map", options->pin_dir);
    int target_map_fd = open_pinned_map(target_map_path);
    if (target_map_fd < 0) {
        fprintf(stderr, "serve: BPF_OBJ_GET(%s) failed: %s\n",
                target_map_path, strerror(errno));
        close(txn_map_fd);
        return 1;
    }

    int server_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server_fd < 0) {
        fprintf(stderr, "serve: socket() failed: %s\n", strerror(errno));
        close(txn_map_fd);
        close(target_map_fd);
        return 1;
    }

    struct sockaddr_un addr;
    socklen_t addr_len = make_sockaddr_un(options->proxy_socket_path, &addr);

    if (!is_abstract_socket_name(options->proxy_socket_path)) {
        unlink(options->proxy_socket_path);
    }
    if (bind(server_fd, (struct sockaddr*)&addr, addr_len) != 0) {
        fprintf(stderr, "serve: bind(%s) failed: %s\n",
                options->proxy_socket_path, strerror(errno));
        close(server_fd);
        close(txn_map_fd);
        close(target_map_fd);
        return 1;
    }
    if (!is_abstract_socket_name(options->proxy_socket_path)) {
        chmod(options->proxy_socket_path, 0666);
    }

    if (listen(server_fd, 4) != 0) {
        fprintf(stderr, "serve: listen() failed: %s\n", strerror(errno));
        close(server_fd);
        close(txn_map_fd);
        close(target_map_fd);
        return 1;
    }

    fprintf(stdout, "serve: proxy listening at %s\n", options->proxy_socket_path);
    fflush(stdout);

    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "serve: accept() failed: %s\n", strerror(errno));
            break;
        }
        struct proxy_client_args* client_args = calloc(1, sizeof(*client_args));
        if (!client_args) {
            fprintf(stderr, "serve: calloc() failed for client args\n");
            close(client_fd);
            continue;
        }
        client_args->client_fd = client_fd;
        client_args->txn_map_fd = txn_map_fd;
        client_args->target_map_fd = target_map_fd;
        client_args->target_pid = 0;
        client_args->session.listener_fd = -1;
        client_args->session.txn_map_fd = -1;
        if (pthread_mutex_init(&client_args->session.mutex, NULL) != 0) {
            fprintf(stderr, "serve: session init failed\n");
            close(client_fd);
            free(client_args);
            continue;
        }
        if (pthread_cond_init(&client_args->session.cond, NULL) != 0) {
            fprintf(stderr, "serve: session init failed\n");
            pthread_mutex_destroy(&client_args->session.mutex);
            close(client_fd);
            free(client_args);
            continue;
        }

        pthread_t thread;
        int rc = pthread_create(&thread, NULL, handle_proxy_client_thread, client_args);
        if (rc != 0) {
            fprintf(stderr, "serve: pthread_create() failed: %s\n", strerror(rc));
            close(client_fd);
            free(client_args);
            continue;
        }
        pthread_detach(thread);
    }

    close(server_fd);
    close(txn_map_fd);
    close(target_map_fd);
    if (!is_abstract_socket_name(options->proxy_socket_path)) {
        unlink(options->proxy_socket_path);
    }
    return 0;
}

int main(int argc, char** argv)
{
    struct options options;

    libbpf_set_print(libbpf_logger);

    if (parse_args(argc, argv, &options) != 0) {
        usage(stderr, argv[0]);
        return 1;
    }

    if (options.unload_only) {
        return unload_pins(&options);
    }
    if (options.serve) {
        return do_serve(&options); /* covers both "serve --pid" and "daemon" */
    }
    return do_load(&options);
}
