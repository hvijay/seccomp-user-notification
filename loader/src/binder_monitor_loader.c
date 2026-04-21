#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>

#include "../compat/libbpf_min.h"
#include "shared_types.h"

#define DEFAULT_BPF_OBJ "/data/local/tmp/binder_monitor.bpf.o"
#define DEFAULT_PIN_DIR "/sys/fs/bpf/binder_monitor"
#define DEFAULT_LINK_PATH DEFAULT_PIN_DIR "/link"
#define DEFAULT_TXN_MAP_PATH DEFAULT_PIN_DIR "/txn_map"
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

static void handle_proxy_client(int client_fd, int txn_map_fd, int target_map_fd)
{
    uint8_t msg_type;
    while (read_full(client_fd, &msg_type, 1) == 1) {
        if (msg_type == PROXY_MSG_SET_TARGET) {
            uint32_t pid = 0;
            if (read_full(client_fd, &pid, sizeof(pid)) != (ssize_t)sizeof(pid)) {
                break;
            }
            uint64_t cgroup_id = 0;
            uint8_t ok = 1;
            if (pid == 0) {
                /* clear filter */
                uint32_t zero = 0;
                if (sys_bpf_map_update_elem(target_map_fd, &zero, &cgroup_id, 0) != 0) {
                    fprintf(stderr, "proxy: SET_TARGET clear failed: %s\n", strerror(errno));
                    ok = 0;
                } else {
                    fprintf(stdout, "proxy: monitoring disabled\n");
                    fflush(stdout);
                }
            } else {
                char cgroup_path[PATH_MAX];
                struct stat st;
                if (read_cgroup_path_for_pid((pid_t)pid, cgroup_path, sizeof(cgroup_path)) != 0 ||
                    stat(cgroup_path, &st) != 0) {
                    fprintf(stderr, "proxy: SET_TARGET pid=%u cgroup resolve failed: %s\n",
                            pid, strerror(errno));
                    ok = 0;
                } else {
                    cgroup_id = (uint64_t)st.st_ino;
                    uint32_t zero = 0;
                    if (sys_bpf_map_update_elem(target_map_fd, &zero, &cgroup_id, 0) != 0) {
                        fprintf(stderr, "proxy: SET_TARGET map update failed: %s\n", strerror(errno));
                        ok = 0;
                    } else {
                        fprintf(stdout, "proxy: monitoring pid=%u cgroup=%s id=%llu\n",
                                pid, cgroup_path, (unsigned long long)cgroup_id);
                        fflush(stdout);
                    }
                }
            }
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
            if (sys_bpf_map_lookup_and_delete_elem(txn_map_fd, &tid, &info) == 0) {
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

struct proxy_client_args {
    int client_fd;
    int txn_map_fd;
    int target_map_fd;
};

static void* handle_proxy_client_thread(void* opaque)
{
    struct proxy_client_args* args = (struct proxy_client_args*)opaque;
    handle_proxy_client(args->client_fd, args->txn_map_fd, args->target_map_fd);
    close(args->client_fd);
    free(args);
    return NULL;
}

static int unload_pins(const struct options* options)
{
    char target_map_path[PATH_MAX];
    snprintf(target_map_path, sizeof(target_map_path), "%s/target_cgroup_map", options->pin_dir);

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
    if (rmdir(options->pin_dir) != 0 && errno != ENOENT && errno != ENOTEMPTY) {
        fprintf(stderr, "failed to remove pin dir %s: %s\n",
                options->pin_dir, strerror(errno));
        status = 1;
    }
    return status;
}

static int do_load(const struct options* options)
{
    char cgroup_path[PATH_MAX];
    struct stat cgroup_stat;
    struct bpf_object* obj = NULL;
    struct bpf_program* prog;
    struct bpf_link* link = NULL;
    uint32_t zero = 0;
    uint64_t target_cgroup_id = 0;
    int target_map_fd = -1;
    int txn_map_fd = -1;
    int status = 1;

    if (options->target_pid > 0) {
        if (read_cgroup_path_for_pid(options->target_pid, cgroup_path, sizeof(cgroup_path)) != 0) {
            fprintf(stderr, "failed to resolve cgroup for pid %d: %s\n",
                    options->target_pid, strerror(errno));
            goto out;
        }
        if (stat(cgroup_path, &cgroup_stat) != 0) {
            fprintf(stderr, "failed to stat cgroup %s: %s\n", cgroup_path, strerror(errno));
            goto out;
        }
        target_cgroup_id = (uint64_t)cgroup_stat.st_ino;
    } else {
        /* daemon mode: start with cgroup_id=0 (disabled); policydaemon will SET_TARGET later */
        cgroup_path[0] = '\0';
        target_cgroup_id = 0;
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
    snprintf(stale_target_map_path, sizeof(stale_target_map_path),
             "%s/target_cgroup_map", options->pin_dir);
    if (unlink_if_exists(stale_target_map_path) != 0) {
        fprintf(stderr, "failed to clear stale map pin %s: %s\n",
                stale_target_map_path, strerror(errno));
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
    if (sys_bpf_map_update_elem(target_map_fd, &zero, &target_cgroup_id, 0) != 0) {
        fprintf(stderr, "failed to set target cgroup id %llu: %s\n",
                (unsigned long long)target_cgroup_id, strerror(errno));
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

    link = bpf_program__attach_tracepoint(prog, "raw_syscalls", "sys_enter");
    if (!link || libbpf_get_error(link)) {
        fprintf(stderr, "failed to attach binder_monitor to raw_syscalls/sys_enter\n");
        link = NULL;
        goto out;
    }
    if (bpf_link__pin(link, options->link_path) != 0) {
        fprintf(stderr, "failed to pin link at %s\n", options->link_path);
        goto out;
    }

    if (options->target_pid > 0) {
        fprintf(stdout,
                "loaded %s for pid=%d cgroup=%s cgroup_id=%llu\n"
                "pinned link=%s\n"
                "pinned txn_map=%s\n",
                options->bpf_obj_path,
                options->target_pid,
                cgroup_path,
                (unsigned long long)target_cgroup_id,
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
        snprintf(cleanup_target_path, sizeof(cleanup_target_path),
                 "%s/target_cgroup_map", options->pin_dir);
        unlink_if_exists(cleanup_target_path);
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
