#include <android/log.h>
#include <jni.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <string>

namespace {

#if defined(__aarch64__)
constexpr uint32_t kAuditArch = AUDIT_ARCH_AARCH64;
#elif defined(__x86_64__)
constexpr uint32_t kAuditArch = AUDIT_ARCH_X86_64;
#else
#error Unsupported architecture
#endif

struct WorkerResult {
    int listener_fd = -1;
    int child_pid = -1;
    int result_read_fd = -1;
};

struct WorkerArgs {
    std::string path;
    WorkerResult* result;
};

int InstallUserNotifyFilter() {
    sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kAuditArch, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    sock_fprog prog = {
        .len = static_cast<unsigned short>(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        return -errno;
    }

    int fd = static_cast<int>(syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                                      SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog));
    if (fd < 0) {
        return -errno;
    }
    return fd;
}

void* WorkerMain(void* opaque) {
    auto* args = static_cast<WorkerArgs*>(opaque);
    auto* result = args->result;

    const int listener_fd = InstallUserNotifyFilter();
    if (listener_fd < 0) {
        result->listener_fd = listener_fd;
        return nullptr;
    }

    int result_pipe[2];
    if (pipe2(result_pipe, O_CLOEXEC) != 0) {
        const int saved_errno = errno;
        close(listener_fd);
        result->listener_fd = -saved_errno;
        result->child_pid = -1;
        return nullptr;
    }

    const pid_t pid = fork();
    if (pid < 0) {
        const int saved_errno = errno;
        close(result_pipe[0]);
        close(result_pipe[1]);
        close(listener_fd);
        result->listener_fd = -saved_errno;
        result->child_pid = -1;
        return nullptr;
    }

    if (pid == 0) {
        close(result_pipe[0]);

        long fd = syscall(__NR_openat, AT_FDCWD, args->path.c_str(), O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) {
            std::array<char, 4096> buffer{};
            const ssize_t read_count = TEMP_FAILURE_RETRY(read(static_cast<int>(fd), buffer.data(),
                                                               buffer.size() - 1));
            syscall(__NR_close, fd);
            if (read_count >= 0) {
                static constexpr char kPrefix[] = "OK\n";
                TEMP_FAILURE_RETRY(write(result_pipe[1], kPrefix, sizeof(kPrefix) - 1));
                if (read_count > 0) {
                    TEMP_FAILURE_RETRY(write(result_pipe[1], buffer.data(), read_count));
                }
            } else {
                const std::string message = "ERR\nRead failed after allow. errno=" +
                                            std::to_string(errno) + "\n";
                TEMP_FAILURE_RETRY(write(result_pipe[1], message.data(), message.size()));
            }
            close(result_pipe[1]);
            _exit(0);
        }

        const std::string message =
                "ERR\nRequest blocked or syscall failed. errno=" + std::to_string(errno) + "\n";
        TEMP_FAILURE_RETRY(write(result_pipe[1], message.data(), message.size()));
        close(result_pipe[1]);
        _exit(errno == 0 ? 1 : errno);
    }

    close(result_pipe[1]);
    result->listener_fd = listener_fd;
    result->child_pid = static_cast<int>(pid);
    result->result_read_fd = result_pipe[0];
    return nullptr;
}

}  // namespace

extern "C" JNIEXPORT jintArray JNICALL
Java_com_example_seccomp_demoapp_NativeSeccompBridge_installFilterForkAndTrigger(
        JNIEnv* env, jclass, jstring path_j) {
    const char* raw_path = env->GetStringUTFChars(path_j, nullptr);
    WorkerResult result;
    WorkerArgs args{
        .path = raw_path != nullptr ? raw_path : "/proc/version",
        .result = &result,
    };
    if (raw_path != nullptr) {
        env->ReleaseStringUTFChars(path_j, raw_path);
    }

    pthread_t thread;
    const int create_rc = pthread_create(&thread, nullptr, &WorkerMain, &args);
    if (create_rc != 0) {
        result.listener_fd = -create_rc;
        result.child_pid = -1;
    } else {
        pthread_join(thread, nullptr);
    }

    const jint values[3] = {result.listener_fd, result.child_pid, result.result_read_fd};
    jintArray output = env->NewIntArray(3);
    if (output == nullptr) {
        return nullptr;
    }
    env->SetIntArrayRegion(output, 0, 3, values);
    return output;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_seccomp_demoapp_NativeSeccompBridge_readChildResult(
        JNIEnv* env, jclass, jint read_fd) {
    if (read_fd < 0) {
        return env->NewStringUTF("Invalid child result pipe.");
    }

    std::string output;
    std::array<char, 4096> buffer{};
    for (;;) {
        const ssize_t n = TEMP_FAILURE_RETRY(read(read_fd, buffer.data(), buffer.size()));
        if (n == 0) {
            break;
        }
        if (n < 0) {
            close(read_fd);
            const std::string error = "Failed to read child result. errno=" + std::to_string(errno);
            return env->NewStringUTF(error.c_str());
        }
        output.append(buffer.data(), static_cast<size_t>(n));
    }
    close(read_fd);

    if (output.rfind("OK\n", 0) == 0) {
        const std::string message = "Allowed. /proc/version contents:\n" + output.substr(3);
        return env->NewStringUTF(message.c_str());
    }
    if (output.rfind("ERR\n", 0) == 0) {
        const std::string message = "Blocked or failed:\n" + output.substr(4);
        return env->NewStringUTF(message.c_str());
    }
    if (output.empty()) {
        return env->NewStringUTF("Child exited without reporting a result.");
    }
    return env->NewStringUTF(output.c_str());
}
