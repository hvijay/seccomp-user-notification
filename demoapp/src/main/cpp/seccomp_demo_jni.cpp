#include <jni.h>
#include <linux/android/binder.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <string>
#include <vector>

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
    std::string action;
    std::string target_package;
    std::string target_component;
    std::string data_uri;
    WorkerResult* result;
};

int InstallUserNotifyFilter() {
    constexpr uint32_t kBinderWriteReadLow = static_cast<uint32_t>(BINDER_WRITE_READ);
    constexpr uint32_t kBinderWriteReadHigh = static_cast<uint32_t>(
            static_cast<uint64_t>(BINDER_WRITE_READ) >> 32U);

    sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kAuditArch, 0, 7),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 5),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args[1])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kBinderWriteReadLow, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args[1]) + 4),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kBinderWriteReadHigh, 0, 1),
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

[[noreturn]] void ExecBroadcastIntent(const WorkerArgs& args, int write_fd) {
    TEMP_FAILURE_RETRY(dup2(write_fd, STDOUT_FILENO));
    TEMP_FAILURE_RETRY(dup2(write_fd, STDERR_FILENO));
    if (write_fd != STDOUT_FILENO && write_fd != STDERR_FILENO) {
        close(write_fd);
    }

    std::vector<char*> argv;
    argv.push_back(const_cast<char*>("/system/bin/am"));
    argv.push_back(const_cast<char*>("broadcast"));
    argv.push_back(const_cast<char*>("-a"));
    argv.push_back(const_cast<char*>(args.action.c_str()));
    if (!args.data_uri.empty()) {
        argv.push_back(const_cast<char*>("-d"));
        argv.push_back(const_cast<char*>(args.data_uri.c_str()));
    }
    if (!args.target_package.empty()) {
        argv.push_back(const_cast<char*>("-p"));
        argv.push_back(const_cast<char*>(args.target_package.c_str()));
    }
    if (!args.target_component.empty()) {
        argv.push_back(const_cast<char*>("-n"));
        argv.push_back(const_cast<char*>(args.target_component.c_str()));
    }
    argv.push_back(const_cast<char*>("--es"));
    argv.push_back(const_cast<char*>("source"));
    argv.push_back(const_cast<char*>("native-fork-child"));
    argv.push_back(nullptr);

    execv(argv[0], argv.data());

    const std::string message = "execv(/system/bin/am) failed. errno=" + std::to_string(errno) + "\n";
    TEMP_FAILURE_RETRY(write(STDERR_FILENO, message.data(), message.size()));
    _exit(errno == 0 ? 127 : errno);
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
        close(listener_fd);
        ExecBroadcastIntent(*args, result_pipe[1]);
    }

    close(result_pipe[1]);
    result->listener_fd = listener_fd;
    result->child_pid = static_cast<int>(pid);
    result->result_read_fd = result_pipe[0];
    return nullptr;
}

std::string CopyJString(JNIEnv* env, jstring value, const char* fallback) {
    if (value == nullptr) {
        return fallback;
    }
    const char* raw = env->GetStringUTFChars(value, nullptr);
    std::string out = raw != nullptr ? raw : fallback;
    if (raw != nullptr) {
        env->ReleaseStringUTFChars(value, raw);
    }
    return out;
}

}  // namespace

extern "C" JNIEXPORT jintArray JNICALL
Java_com_example_seccomp_demoapp_NativeSeccompBridge_installFilterForkAndTriggerIntent(
        JNIEnv* env, jclass, jstring action_j, jstring target_package_j,
        jstring target_component_j, jstring data_uri_j) {
    WorkerResult result;
    WorkerArgs args{
        .action = CopyJString(env, action_j, "com.example.seccomp.demoapp.NATIVE_POC"),
        .target_package = CopyJString(env, target_package_j, "com.example.seccomp.demoapp"),
        .target_component = CopyJString(env, target_component_j, ""),
        .data_uri = CopyJString(env, data_uri_j, "https://example.com/seccomp-poc"),
        .result = &result,
    };

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

    if (output.empty()) {
        return env->NewStringUTF(
                "Child exited without producing any command output. If the request was denied, inspect logcat for the `am broadcast` failure.");
    }

    const std::string message = "Forked child command output:\n" + output;
    return env->NewStringUTF(message.c_str());
}
