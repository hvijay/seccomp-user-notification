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

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_seccomp_policydaemon_SeccompNativeBridge_nativeStartMonitoring(
        JNIEnv* env, jclass, jstring session_id_j, jint target_pid) {
    const std::string session_id = CopyJString(env, session_id_j);
    if (session_id.empty() || target_pid <= 0) {
        return JNI_FALSE;
    }

    auto session = std::make_shared<Session>();
    session->id = session_id;
    session->target_pid = target_pid;
    session->proxy_fd = ConnectToProxySocket();
    if (session->proxy_fd < 0) {
        return JNI_FALSE;
    }
    if (!SendSetTarget(session->proxy_fd, static_cast<uint32_t>(target_pid))) {
        close(session->proxy_fd);
        return JNI_FALSE;
    }

    std::lock_guard<std::mutex> lock(g_sessions_mutex);
    if (g_sessions.contains(session_id)) {
        close(session->proxy_fd);
        return JNI_FALSE;
    }
    g_sessions.emplace(session_id, session);
    return JNI_TRUE;
}

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
        SendSetTarget(session->proxy_fd, 0);
        close(session->proxy_fd);
        session->proxy_fd = -1;
    }
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}
