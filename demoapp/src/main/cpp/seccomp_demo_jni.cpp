#include <jni.h>
#include <android/log.h>
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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <string>

namespace {

constexpr const char* kTag = "SeccompDemoJNI";

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
    int go_write_fd = -1;  /* parent writes here to unblock child after session is registered */
};

struct WorkerArgs {
    std::string action;
    std::string target_package;
    std::string target_component;
    std::string data_uri;
    int go_read_fd = -1;
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

int SendListenerFd(int sock_fd, int listener_fd, int status) {
    struct msghdr msg = {};
    struct iovec iov;
    iov.iov_base = &status;
    iov.iov_len = sizeof(status);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    char control[CMSG_SPACE(sizeof(int))];
    if (listener_fd >= 0) {
        memset(control, 0, sizeof(control));
        msg.msg_control = control;
        msg.msg_controllen = sizeof(control);

        struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &listener_fd, sizeof(listener_fd));
    }

    return TEMP_FAILURE_RETRY(sendmsg(sock_fd, &msg, 0));
}

int ReceiveListenerFd(int sock_fd, int* out_status) {
    struct msghdr msg = {};
    struct iovec iov;
    int status = -EINVAL;
    iov.iov_base = &status;
    iov.iov_len = sizeof(status);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    char control[CMSG_SPACE(sizeof(int))];
    memset(control, 0, sizeof(control));
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    const ssize_t n = TEMP_FAILURE_RETRY(recvmsg(sock_fd, &msg, 0));
    if (n != static_cast<ssize_t>(sizeof(status))) {
        if (out_status != nullptr) {
            *out_status = -EIO;
        }
        return -1;
    }

    if (out_status != nullptr) {
        *out_status = status;
    }

    for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
         cmsg != nullptr;
         cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET &&
            cmsg->cmsg_type == SCM_RIGHTS &&
            cmsg->cmsg_len >= CMSG_LEN(sizeof(int))) {
            int received_fd = -1;
            memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(received_fd));
            return received_fd;
        }
    }
    return -1;
}

/*
 * Write a 4-byte little-endian uint32 into buf at offset off; return new offset.
 */
static uint32_t ParcelWriteU32(uint8_t* buf, uint32_t off, uint32_t val) {
    memcpy(buf + off, &val, 4);
    return off + 4;
}

/*
 * Write an Android String16 (Parcel format) into buf.
 * Null/empty string is written as length=-1 (0xFFFFFFFF).
 * Non-empty strings are length(u32) + UTF-16LE chars + 4-byte alignment pad.
 */
static uint32_t ParcelWriteStr16(uint8_t* buf, uint32_t off, const char* s) {
    if (!s || !s[0]) {
        return ParcelWriteU32(buf, off, static_cast<uint32_t>(-1));
    }
    uint32_t len = static_cast<uint32_t>(strlen(s));
    off = ParcelWriteU32(buf, off, len);
    for (uint32_t i = 0; i < len; ++i) {
        buf[off + i * 2]     = static_cast<uint8_t>(s[i]);
        buf[off + i * 2 + 1] = 0;
    }
    off += len * 2;
    buf[off++] = 0;  /* UTF-16 null terminator low byte */
    buf[off++] = 0;  /* UTF-16 null terminator high byte */
    while (off % 4 != 0) buf[off++] = 0;
    return off;
}

/*
 * Instead of exec-ing `am start` (which fails because the forked child has the
 * app UID but am identifies itself as com.android.shell), build a raw Binder
 * BC_TRANSACTION directly on a fresh /dev/binder fd.
 *
 * The parcel is crafted to match what the eBPF monitor expects:
 *   strict_mode(u32) | work_source_uid(u32) | interface(str16)
 *   | action(str16) | uri(str16) | pkg(str16)
 *
 * seccomp intercepts the BINDER_WRITE_READ ioctl, eBPF captures the parcel,
 * and the policydaemon shows the allow/deny prompt.
 */
[[noreturn]] void DoBinderTransaction(const WorkerArgs& args, int write_fd) {
    /* Keep output on the result pipe so Kotlin can read it. */
    TEMP_FAILURE_RETRY(dup2(write_fd, STDOUT_FILENO));
    TEMP_FAILURE_RETRY(dup2(write_fd, STDERR_FILENO));
    if (write_fd != STDOUT_FILENO && write_fd != STDERR_FILENO) close(write_fd);

    /*
     * Block until the parent signals us (after registerSession completes and
     * SET_TARGET has been sent to the loader, arming the BPF cgroup filter).
     * Without this, the BPF tracepoint fires with target_cgroup_id=0 and skips
     * recording, so the lookup returns found=false and the notification is
     * auto-allowed without ever reaching the policydaemon UI.
     */
    if (args.go_read_fd >= 0) {
        uint8_t dummy = 0;
        TEMP_FAILURE_RETRY(read(args.go_read_fd, &dummy, 1));
        close(args.go_read_fd);
    }

    /* Debug: print child PID and cgroup so we can verify BPF targeting. */
    {
        char cgroup_buf[256] = {};
        int cg_fd = open("/proc/self/cgroup", O_RDONLY);
        if (cg_fd >= 0) {
            ssize_t n = read(cg_fd, cgroup_buf, sizeof(cgroup_buf) - 1);
            if (n > 0) cgroup_buf[n] = '\0';
            close(cg_fd);
        }
        dprintf(STDOUT_FILENO, "child pid=%d cgroup=%s\n", getpid(), cgroup_buf);
    }

    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (bfd < 0) { _exit(1); }

    struct binder_version ver = {};
    if (ioctl(bfd, BINDER_VERSION, &ver) != 0) { _exit(1); }

    uint32_t max_threads = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &max_threads);

    /* Build an IContentProvider.query() Parcel for content://com.android.calendar/events.
     *
     * Header:  strict_mode(u32) | work_source_uid(u32) | interface(str16)
     * Params:  callingPkg(str16) | callingFeatureId(null str16, API 30+)
     *        | Uri: int32(3=HierarchicalUri) | scheme(str16)
     *               | authority Part: int32(1=ENCODED) str16
     *               | path Part:      int32(1=ENCODED) str16
     *               | query Part:     int32(-1=null)
     *               | fragment Part:  int32(-1=null)
     */
    uint8_t parcel[1024] = {};
    uint32_t poff = 0;
    poff = ParcelWriteU32(parcel, poff, 0);        /* strict_mode */
    poff = ParcelWriteU32(parcel, poff, ~0u);       /* work_source_uid */
    poff = ParcelWriteStr16(parcel, poff, "android.content.IContentProvider");
    poff = ParcelWriteStr16(parcel, poff, "com.example.seccomp.demoapp"); /* callingPkg */
    poff = ParcelWriteU32(parcel, poff, static_cast<uint32_t>(-1));       /* callingFeatureId null */
    /* Uri: StringUri (type=1) — single UTF-16 string, unambiguous for Parcel readers. */
    poff = ParcelWriteU32(parcel, poff, 1);
    poff = ParcelWriteStr16(parcel, poff, "content://com.android.calendar/events");

    /* binder_transaction_data: TF_ONE_WAY so no reply is expected. */
    struct binder_transaction_data txn = {};
    txn.target.handle         = 1;   /* any registered service handle */
    txn.code                  = 1;   /* TRANSACTION_query */
    txn.flags                 = TF_ONE_WAY;
    txn.data_size             = poff;
    txn.data.ptr.buffer       = reinterpret_cast<binder_uintptr_t>(parcel);
    txn.offsets_size          = 0;
    txn.data.ptr.offsets      = 0;

    /* Write buffer: BC_TRANSACTION command + transaction data. */
    const uint32_t bcmd = BC_TRANSACTION;
    uint8_t wbuf[sizeof(bcmd) + sizeof(txn)];
    memcpy(wbuf, &bcmd, sizeof(bcmd));
    memcpy(wbuf + sizeof(bcmd), &txn, sizeof(txn));

    /* Read buffer: needed to receive BR_TRANSACTION_COMPLETE from the driver. */
    uint8_t rbuf[256] = {};

    struct binder_write_read bwr = {};
    bwr.write_buffer   = reinterpret_cast<binder_uintptr_t>(wbuf);
    bwr.write_size     = sizeof(wbuf);
    bwr.read_buffer    = reinterpret_cast<binder_uintptr_t>(rbuf);
    bwr.read_size      = sizeof(rbuf);

    /*
     * This ioctl(BINDER_WRITE_READ) is intercepted by seccomp → frozen until
     * the policydaemon responds.  The Binder metadata capture now runs from
     * the seccomp path before the task is parked for USER_NOTIF handling.
     */
    int rc = ioctl(bfd, BINDER_WRITE_READ, &bwr);

    static const char kAllowed[] = "Calendar query ioctl submitted (seccomp allowed).\n";
    static const char kDenied[]  = "Calendar query ioctl denied by policy.\n";
    const char* msg = (rc == 0 || errno != EPERM) ? kAllowed : kDenied;
    TEMP_FAILURE_RETRY(write(STDOUT_FILENO, msg, strlen(msg)));
    close(bfd);
    _exit(0);
}

void* WorkerMain(void* opaque) {
    auto* args = static_cast<WorkerArgs*>(opaque);
    auto* result = args->result;

    int result_pipe[2];
    if (pipe2(result_pipe, O_CLOEXEC) != 0) {
        const int saved_errno = errno;
        result->listener_fd = -saved_errno;
        result->child_pid = -1;
        return nullptr;
    }

    int go_pipe[2];
    if (pipe2(go_pipe, O_CLOEXEC) != 0) {
        const int saved_errno = errno;
        close(result_pipe[0]);
        close(result_pipe[1]);
        result->listener_fd = -saved_errno;
        result->child_pid = -1;
        return nullptr;
    }

    int listener_sock[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, listener_sock) != 0) {
        const int saved_errno = errno;
        close(result_pipe[0]);
        close(result_pipe[1]);
        close(go_pipe[0]);
        close(go_pipe[1]);
        result->listener_fd = -saved_errno;
        result->child_pid = -1;
        return nullptr;
    }

    const pid_t pid = fork();
    if (pid < 0) {
        const int saved_errno = errno;
        close(result_pipe[0]);
        close(result_pipe[1]);
        close(go_pipe[0]);
        close(go_pipe[1]);
        close(listener_sock[0]);
        close(listener_sock[1]);
        result->listener_fd = -saved_errno;
        result->child_pid = -1;
        return nullptr;
    }

    if (pid == 0) {
        close(listener_sock[0]);
        close(result_pipe[0]);
        close(go_pipe[1]);
        const int listener_fd = InstallUserNotifyFilter();
        const int status = listener_fd >= 0 ? 0 : listener_fd;
        SendListenerFd(listener_sock[1], listener_fd >= 0 ? listener_fd : -1, status);
        close(listener_sock[1]);
        if (listener_fd < 0) {
            _exit(1);
        }
        args->go_read_fd = go_pipe[0];
        DoBinderTransaction(*args, result_pipe[1]);
    }

    close(listener_sock[1]);
    close(result_pipe[1]);
    close(go_pipe[0]);
    int listener_status = -EIO;
    const int received_listener_fd = ReceiveListenerFd(listener_sock[0], &listener_status);
    close(listener_sock[0]);
    result->listener_fd = received_listener_fd >= 0 ? received_listener_fd : listener_status;
    result->child_pid = static_cast<int>(pid);
    result->result_read_fd = result_pipe[0];
    result->go_write_fd = go_pipe[1];
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
        .action = CopyJString(env, action_j, "android.intent.action.VIEW"),
        .target_package = CopyJString(env, target_package_j, ""),
        .target_component = CopyJString(env, target_component_j, ""),
        .data_uri = CopyJString(env, data_uri_j, "https://example.com/"),
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

    const jint values[4] = {result.listener_fd, result.child_pid, result.result_read_fd, result.go_write_fd};
    jintArray output = env->NewIntArray(4);
    if (output == nullptr) {
        return nullptr;
    }
    env->SetIntArrayRegion(output, 0, 4, values);
    return output;
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_seccomp_demoapp_NativeSeccompBridge_triggerChild(
        JNIEnv*, jclass, jint go_write_fd) {
    if (go_write_fd >= 0) {
        uint8_t go = 1;
        TEMP_FAILURE_RETRY(write(go_write_fd, &go, 1));
        close(go_write_fd);
    }
}

extern "C" JNIEXPORT jlongArray JNICALL
Java_com_example_seccomp_demoapp_NativeSeccompBridge_awaitNotification(
        JNIEnv* env, jclass, jint listener_fd) {
    jlong values[5] = {-static_cast<jlong>(EINVAL), 0, 0, 0, 0};
    seccomp_notif request = {};
    if (ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &request) == 0) {
        __android_log_print(
                ANDROID_LOG_INFO,
                kTag,
                "SECCOMP_IOCTL_NOTIF_RECV ok fd=%d id=%llu pid=%d nr=%d arg1=%llu",
                listener_fd,
                static_cast<unsigned long long>(request.id),
                request.pid,
                request.data.nr,
                static_cast<unsigned long long>(request.data.args[1]));
        values[0] = 0;
        values[1] = static_cast<jlong>(request.id);
        values[2] = static_cast<jlong>(request.pid);
        values[3] = static_cast<jlong>(request.data.nr);
        values[4] = static_cast<jlong>(request.data.args[1]);
    } else {
        __android_log_print(
                ANDROID_LOG_ERROR,
                kTag,
                "SECCOMP_IOCTL_NOTIF_RECV failed fd=%d errno=%d (%s)",
                listener_fd,
                errno,
                strerror(errno));
        values[0] = -static_cast<jlong>(errno);
    }
    jlongArray output = env->NewLongArray(5);
    if (output == nullptr) {
        return nullptr;
    }
    env->SetLongArrayRegion(output, 0, 5, values);
    return output;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_seccomp_demoapp_NativeSeccompBridge_respondNotification(
        JNIEnv*, jclass, jint listener_fd, jlong notification_id, jboolean allow, jint deny_errno) {
    seccomp_notif_resp response{};
    response.id = static_cast<uint64_t>(notification_id);
    response.val = allow ? 0 : -1;
    response.error = allow ? 0 : -deny_errno;
    response.flags = allow ? SECCOMP_USER_NOTIF_FLAG_CONTINUE : 0;
    if (ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &response) != 0) {
        __android_log_print(
                ANDROID_LOG_ERROR,
                kTag,
                "SECCOMP_IOCTL_NOTIF_SEND failed fd=%d id=%llu errno=%d (%s)",
                listener_fd,
                static_cast<unsigned long long>(notification_id),
                errno,
                strerror(errno));
        return JNI_FALSE;
    }
    __android_log_print(
            ANDROID_LOG_INFO,
            kTag,
            "SECCOMP_IOCTL_NOTIF_SEND ok fd=%d id=%llu allow=%d",
            listener_fd,
            static_cast<unsigned long long>(notification_id),
            allow ? 1 : 0);
    return JNI_TRUE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_seccomp_demoapp_NativeSeccompBridge_closeFd(
        JNIEnv*, jclass, jint fd) {
    if (fd >= 0) {
        close(fd);
    }
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
        return env->NewStringUTF("Child exited without output.");
    }

    const std::string message = "Child result: " + output;
    return env->NewStringUTF(message.c_str());
}
