#include <android/log.h>
#include <jni.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <sys/socket.h>

#include "../../../../common/shared_types.h"

namespace {

constexpr const char* kTag = "SeccompPolicyJNI";
constexpr const char* kProxySocketPath = "@binder_monitor_proxy";

struct Session {
    std::string id;
    int target_pid = -1;
    int proxy_fd = -1;
};

std::mutex g_sessions_mutex;
std::unordered_map<std::string, std::shared_ptr<Session>> g_sessions;

static int ConnectToProxySocket();
static std::string CopyJString(JNIEnv* env, jstring value);

void LogError(const char* message) {
    __android_log_print(ANDROID_LOG_ERROR, kTag, "%s errno=%d (%s)", message, errno, strerror(errno));
}

static ssize_t ReadFull(int fd, void* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t r = read(fd, static_cast<char*>(buf) + total, n - total);
        if (r <= 0) return r == 0 ? static_cast<ssize_t>(total) : r;
        total += static_cast<size_t>(r);
    }
    return static_cast<ssize_t>(total);
}

static ssize_t WriteFull(int fd, const void* buf, size_t n) {
    size_t written = 0;
    while (written < n) {
        ssize_t r = write(fd, static_cast<const char*>(buf) + written, n - written);
        if (r <= 0) return r == 0 ? static_cast<ssize_t>(written) : r;
        written += static_cast<size_t>(r);
    }
    return static_cast<ssize_t>(written);
}

static bool SendSetTarget(int proxy_fd, uint32_t pid) {
    uint8_t msg = PROXY_MSG_SET_TARGET;
    if (WriteFull(proxy_fd, &msg, 1) != 1 ||
        WriteFull(proxy_fd, &pid, sizeof(pid)) != static_cast<ssize_t>(sizeof(pid))) {
        LogError("SendSetTarget: write failed");
        return false;
    }
    uint8_t ok = 0;
    if (ReadFull(proxy_fd, &ok, 1) != 1) {
        LogError("SendSetTarget: read response failed");
        return false;
    }
    if (!ok) {
        __android_log_print(ANDROID_LOG_ERROR, kTag,
            "SendSetTarget: loader returned error for pid=%u", pid);
        return false;
    }
    return true;
}

static bool SendFdWithStatus(int proxy_fd, int fd_to_send, int status) {
    struct msghdr msg{};
    struct iovec iov{};
    iov.iov_base = &status;
    iov.iov_len = sizeof(status);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    char control[CMSG_SPACE(sizeof(int))];
    memset(control, 0, sizeof(control));
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(fd_to_send));

    return sendmsg(proxy_fd, &msg, 0) == static_cast<ssize_t>(sizeof(status));
}

static bool SendRegisterListener(int proxy_fd, int listener_fd) {
    uint8_t msg = PROXY_MSG_REGISTER_LISTENER;
    if (WriteFull(proxy_fd, &msg, 1) != 1 ||
        !SendFdWithStatus(proxy_fd, listener_fd, 0)) {
        LogError("SendRegisterListener: send failed");
        return false;
    }
    uint8_t ok = 0;
    if (ReadFull(proxy_fd, &ok, 1) != 1) {
        LogError("SendRegisterListener: read response failed");
        return false;
    }
    return ok != 0;
}

static bool SendGetPending(int proxy_fd, proxy_pending_request* out_pending) {
    uint8_t msg = PROXY_MSG_GET_PENDING;
    if (WriteFull(proxy_fd, &msg, 1) != 1) {
        LogError("SendGetPending: write failed");
        return false;
    }
    uint8_t found = 0;
    if (ReadFull(proxy_fd, &found, 1) != 1) {
        LogError("SendGetPending: read found failed");
        return false;
    }
    proxy_pending_request pending{};
    if (ReadFull(proxy_fd, &pending, sizeof(pending)) != static_cast<ssize_t>(sizeof(pending))) {
        LogError("SendGetPending: read pending failed");
        return false;
    }
    if (!found) {
        errno = ENOENT;
        return false;
    }
    *out_pending = pending;
    return true;
}

static bool SendDecision(int proxy_fd, uint64_t notification_id, bool allow) {
    uint8_t msg = PROXY_MSG_SEND_DECISION;
    int32_t allow_int = allow ? 1 : 0;
    if (WriteFull(proxy_fd, &msg, 1) != 1 ||
        WriteFull(proxy_fd, &notification_id, sizeof(notification_id)) != static_cast<ssize_t>(sizeof(notification_id)) ||
        WriteFull(proxy_fd, &allow_int, sizeof(allow_int)) != static_cast<ssize_t>(sizeof(allow_int))) {
        LogError("SendDecision: write failed");
        return false;
    }
    uint8_t ok = 0;
    if (ReadFull(proxy_fd, &ok, 1) != 1) {
        LogError("SendDecision: read response failed");
        return false;
    }
    return ok != 0;
}

static void SendUnregister(int proxy_fd) {
    uint8_t msg = PROXY_MSG_UNREGISTER;
    uint8_t ok = 0;
    if (WriteFull(proxy_fd, &msg, 1) == 1) {
        ReadFull(proxy_fd, &ok, 1);
    }
}

static jobjectArray MakePendingArray(JNIEnv* env, const proxy_pending_request& pending) {
    jclass string_class = env->FindClass("java/lang/String");
    if (string_class == nullptr) {
        return nullptr;
    }
    jobjectArray result = env->NewObjectArray(10, string_class, nullptr);
    if (result == nullptr) {
        return nullptr;
    }

    const std::string notification_id = std::to_string(pending.notification_id);
    const std::string pid = std::to_string(pending.pid);
    const std::string syscall_nr = std::to_string(pending.syscall_nr);
    const std::string ioctl_cmd = std::to_string(pending.ioctl_cmd);
    const std::string binder_code = std::to_string(pending.txn.code);
    const std::string target_handle = std::to_string(pending.txn.target_handle);
    env->SetObjectArrayElement(result, 0, env->NewStringUTF(notification_id.c_str()));
    env->SetObjectArrayElement(result, 1, env->NewStringUTF(pid.c_str()));
    env->SetObjectArrayElement(result, 2, env->NewStringUTF(syscall_nr.c_str()));
    env->SetObjectArrayElement(result, 3, env->NewStringUTF(ioctl_cmd.c_str()));
    env->SetObjectArrayElement(result, 4, env->NewStringUTF(pending.txn.interface));
    env->SetObjectArrayElement(result, 5, env->NewStringUTF(binder_code.c_str()));
    env->SetObjectArrayElement(result, 6, env->NewStringUTF(target_handle.c_str()));
    env->SetObjectArrayElement(result, 7, env->NewStringUTF(pending.txn.intent.action));
    env->SetObjectArrayElement(result, 8, env->NewStringUTF(pending.txn.intent.uri));
    env->SetObjectArrayElement(result, 9, env->NewStringUTF(pending.txn.parcel_truncated ? "true" : "false"));
    return result;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_seccomp_policydaemon_SeccompNativeBridge_nativeRegisterSession(
        JNIEnv* env, jclass, jstring session_id_j, jint target_pid, jint listener_fd) {
    const std::string session_id = CopyJString(env, session_id_j);
    if (session_id.empty() || target_pid <= 0 || listener_fd < 0) {
        return JNI_FALSE;
    }

    auto session = std::make_shared<Session>();
    session->id = session_id;
    session->target_pid = target_pid;
    session->proxy_fd = ConnectToProxySocket();
    if (session->proxy_fd < 0) {
        return JNI_FALSE;
    }
    if (!SendSetTarget(session->proxy_fd, static_cast<uint32_t>(target_pid)) ||
        !SendRegisterListener(session->proxy_fd, listener_fd)) {
        close(session->proxy_fd);
        return JNI_FALSE;
    }

    std::lock_guard<std::mutex> lock(g_sessions_mutex);
    if (g_sessions.contains(session_id)) {
        close(session->proxy_fd);
        return JNI_FALSE;
    }
    g_sessions.emplace(session_id, session);
    return true;
}

static int ConnectToProxySocket() {
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    socklen_t addr_len = sizeof(addr);
    if (kProxySocketPath[0] == '@') {
        size_t name_len = strnlen(kProxySocketPath + 1, sizeof(addr.sun_path) - 1);
        memcpy(addr.sun_path + 1, kProxySocketPath + 1, name_len);
        addr_len = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + name_len);
    } else {
        strncpy(addr.sun_path, kProxySocketPath, sizeof(addr.sun_path) - 1);
    }

    constexpr int kMaxAttempts = 40;
    constexpr useconds_t kRetryDelayUs = 50 * 1000;
    int last_errno = 0;
    for (int attempt = 1; attempt <= kMaxAttempts; ++attempt) {
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            LogError("ConnectToProxySocket: socket() failed");
            return -1;
        }

        if (connect(fd, reinterpret_cast<sockaddr*>(&addr), addr_len) == 0) {
            __android_log_print(ANDROID_LOG_INFO, kTag,
                "ConnectToProxySocket: connected to %s after %d attempt(s)",
                kProxySocketPath, attempt);
            return fd;
        }

        last_errno = errno;
        close(fd);
        if (last_errno != ECONNREFUSED && last_errno != ENOENT) {
            break;
        }
        usleep(kRetryDelayUs);
    }

    __android_log_print(ANDROID_LOG_ERROR, kTag,
        "ConnectToProxySocket: connect(%s) failed after retries: errno=%d (%s)",
        kProxySocketPath, last_errno, strerror(last_errno));
    errno = last_errno;
    return -1;
}

static std::string CopyJString(JNIEnv* env, jstring value) {
    const char* raw = env->GetStringUTFChars(value, nullptr);
    std::string out = raw != nullptr ? raw : "";
    if (raw != nullptr) {
        env->ReleaseStringUTFChars(value, raw);
    }
    return out;
}

}  // namespace

extern "C" JNIEXPORT void JNICALL
Java_com_example_seccomp_policydaemon_SeccompNativeBridge_nativeStopListener(
        JNIEnv* env, jclass, jstring session_id_j) {
    const std::string session_id = CopyJString(env, session_id_j);

    std::shared_ptr<Session> session;
    {
        std::lock_guard<std::mutex> lock(g_sessions_mutex);
        auto it = g_sessions.find(session_id);
        if (it == g_sessions.end()) {
            return;
        }
        session = it->second;
        g_sessions.erase(it);
    }

    if (session->proxy_fd >= 0) {
        SendUnregister(session->proxy_fd);
        SendSetTarget(session->proxy_fd, 0);
        close(session->proxy_fd);
        session->proxy_fd = -1;
    }
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_example_seccomp_policydaemon_SeccompNativeBridge_nativeGetPendingRequest(
        JNIEnv* env, jclass, jstring session_id_j) {
    const std::string session_id = CopyJString(env, session_id_j);
    if (session_id.empty()) {
        return nullptr;
    }

    std::shared_ptr<Session> session;
    {
        std::lock_guard<std::mutex> lock(g_sessions_mutex);
        auto it = g_sessions.find(session_id);
        if (it == g_sessions.end()) {
            return nullptr;
        }
        session = it->second;
    }

    proxy_pending_request pending{};
    if (session->proxy_fd < 0 || !SendGetPending(session->proxy_fd, &pending)) {
        if (errno != ENOENT) {
            __android_log_print(
                ANDROID_LOG_WARN,
                kTag,
                "nativeGetPendingRequest: get pending failed for session=%s errno=%d (%s)",
                session_id.c_str(),
                errno,
                strerror(errno));
        }
        return nullptr;
    }
    return MakePendingArray(env, pending);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_seccomp_policydaemon_SeccompNativeBridge_nativeRespondToPendingRequest(
        JNIEnv* env, jclass, jstring session_id_j, jlong notification_id, jboolean allow) {
    const std::string session_id = CopyJString(env, session_id_j);
    if (session_id.empty()) {
        return JNI_FALSE;
    }

    std::shared_ptr<Session> session;
    {
        std::lock_guard<std::mutex> lock(g_sessions_mutex);
        auto it = g_sessions.find(session_id);
        if (it == g_sessions.end()) {
            return JNI_FALSE;
        }
        session = it->second;
    }

    return (session->proxy_fd >= 0 &&
            SendDecision(session->proxy_fd, static_cast<uint64_t>(notification_id), allow == JNI_TRUE))
            ? JNI_TRUE
            : JNI_FALSE;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}
