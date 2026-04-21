#ifndef SECCOMP_BINDER_MONITOR_LIBBPF_MIN_H_
#define SECCOMP_BINDER_MONITOR_LIBBPF_MIN_H_

#include <stdarg.h>

struct bpf_link;
struct bpf_map;
struct bpf_object;
struct bpf_program;

typedef int (*libbpf_print_fn_t)(int level, const char *format, va_list args);

enum libbpf_print_level {
    LIBBPF_WARN,
    LIBBPF_INFO,
    LIBBPF_DEBUG,
};

int libbpf_set_print(libbpf_print_fn_t fn);
long libbpf_get_error(const void* ptr);

struct bpf_object* bpf_object__open_file(const char* path, const void* opts);
int bpf_object__load(struct bpf_object* obj);
void bpf_object__close(struct bpf_object* object);

struct bpf_program* bpf_object__find_program_by_name(const struct bpf_object* obj,
                                                     const char* name);
struct bpf_map* bpf_object__find_map_by_name(const struct bpf_object* obj,
                                             const char* name);
int bpf_object__find_map_fd_by_name(const struct bpf_object* obj, const char* name);

struct bpf_link* bpf_program__attach_tracepoint(const struct bpf_program* prog,
                                                const char* tp_category,
                                                const char* tp_name);
int bpf_link__pin(struct bpf_link* link, const char* path);
int bpf_link__destroy(struct bpf_link* link);

int bpf_map__pin(struct bpf_map* map, const char* path);

#endif  // SECCOMP_BINDER_MONITOR_LIBBPF_MIN_H_
