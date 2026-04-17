#include <android/log.h>
#include <jni.h>
#include <errno.h>
#include <linux/seccomp.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace {

constexpr const char* kTag = "SeccompPolicyJNI";

JavaVM* g_vm = nullptr;
jclass g_repo_class = nullptr;
jmethodID g_on_notification = nullptr;

struct Session {
    std::string id;
    int fd = -1;
    std::atomic_bool running = true;
    std::thread thread;
};

std::mutex g_sessions_mutex;
std::unordered_map<std::string, std::shared_ptr<Session>> g_sessions;

void LogError(const char* message) {
    __android_log_print(ANDROID_LOG_ERROR, kTag, "%s errno=%d", message, errno);
}

void DeliverNotification(const Session& session, const seccomp_notif& request) {
    JNIEnv* env = nullptr;
    bool should_detach = false;
    if (g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        if (g_vm->AttachCurrentThread(&env, nullptr) != JNI_OK) {
            return;
        }
        should_detach = true;
    }

    jstring session_id = env->NewStringUTF(session.id.c_str());
    env->CallStaticVoidMethod(
        g_repo_class,
        g_on_notification,
        session_id,
        static_cast<jlong>(request.id),
        static_cast<jint>(request.pid),
        static_cast<jint>(request.data.nr));
    env->DeleteLocalRef(session_id);

    if (should_detach) {
        g_vm->DetachCurrentThread();
    }
}

void ListenerMain(std::shared_ptr<Session> session) {
    while (session->running) {
        seccomp_notif request{};
        if (ioctl(session->fd, SECCOMP_IOCTL_NOTIF_RECV, &request) != 0) {
            if (errno == EINTR) {
                continue;
            }
            if (session->running) {
                LogError("SECCOMP_IOCTL_NOTIF_RECV failed");
            }
            break;
        }
        DeliverNotification(*session, request);
    }
}

std::shared_ptr<Session> FindSession(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(g_sessions_mutex);
    auto it = g_sessions.find(session_id);
    if (it == g_sessions.end()) {
        return nullptr;
    }
    return it->second;
}

}  // namespace

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_seccomp_policydaemon_SeccompNativeBridge_nativeStartListener(
        JNIEnv* env, jclass, jstring session_id_j, jint fd) {
    const char* session_id_raw = env->GetStringUTFChars(session_id_j, nullptr);
    const std::string session_id = session_id_raw != nullptr ? session_id_raw : "";
    if (session_id_raw != nullptr) {
        env->ReleaseStringUTFChars(session_id_j, session_id_raw);
    }
    if (session_id.empty() || fd < 0) {
        if (fd >= 0) {
            close(fd);
        }
        return JNI_FALSE;
    }

    auto session = std::make_shared<Session>();
    session->id = session_id;
    session->fd = fd;

    {
        std::lock_guard<std::mutex> lock(g_sessions_mutex);
        if (g_sessions.contains(session_id)) {
            close(fd);
            return JNI_FALSE;
        }
        g_sessions.emplace(session_id, session);
    }

    session->thread = std::thread([session]() { ListenerMain(session); });
    return JNI_TRUE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_seccomp_policydaemon_SeccompNativeBridge_nativeStopListener(
        JNIEnv* env, jclass, jstring session_id_j) {
    const char* session_id_raw = env->GetStringUTFChars(session_id_j, nullptr);
    const std::string session_id = session_id_raw != nullptr ? session_id_raw : "";
    if (session_id_raw != nullptr) {
        env->ReleaseStringUTFChars(session_id_j, session_id_raw);
    }

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

    session->running = false;
    if (session->fd >= 0) {
        close(session->fd);
        session->fd = -1;
    }
    if (session->thread.joinable()) {
        session->thread.join();
    }
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_seccomp_policydaemon_SeccompNativeBridge_nativeRespond(
        JNIEnv* env, jclass, jstring session_id_j, jlong notification_id, jboolean allow,
        jint deny_errno) {
    const char* session_id_raw = env->GetStringUTFChars(session_id_j, nullptr);
    const std::string session_id = session_id_raw != nullptr ? session_id_raw : "";
    if (session_id_raw != nullptr) {
        env->ReleaseStringUTFChars(session_id_j, session_id_raw);
    }

    auto session = FindSession(session_id);
    if (session == nullptr || session->fd < 0) {
        return JNI_FALSE;
    }

    seccomp_notif_resp response{};
    response.id = static_cast<uint64_t>(notification_id);
    response.val = allow ? 0 : -1;
    response.error = allow ? 0 : -deny_errno;
    response.flags = allow ? SECCOMP_USER_NOTIF_FLAG_CONTINUE : 0;

    if (ioctl(session->fd, SECCOMP_IOCTL_NOTIF_SEND, &response) != 0) {
        LogError("SECCOMP_IOCTL_NOTIF_SEND failed");
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_vm = vm;

    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    jclass local_repo = env->FindClass("com/example/seccomp/policydaemon/SeccompRepository");
    if (local_repo == nullptr) {
        return JNI_ERR;
    }
    g_repo_class = reinterpret_cast<jclass>(env->NewGlobalRef(local_repo));
    env->DeleteLocalRef(local_repo);
    if (g_repo_class == nullptr) {
        return JNI_ERR;
    }

    g_on_notification = env->GetStaticMethodID(
        g_repo_class,
        "onNativeNotification",
        "(Ljava/lang/String;JII)V");
    if (g_on_notification == nullptr) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}
