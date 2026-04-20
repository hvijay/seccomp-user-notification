#include <android/log.h>
#include <jni.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/seccomp.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>

#include "../../../../common/shared_types.h"

namespace {

constexpr const char* kTag = "SeccompPolicyJNI";
constexpr const char* kPinnedTxnMapPath = "/sys/fs/bpf/binder_monitor/txn_map";

JavaVM* g_vm = nullptr;
jclass g_repo_class = nullptr;
jmethodID g_on_notification = nullptr;

struct TxnLookupResult {
    binder_txn_info info{};
    std::string status;
    bool found = false;
};

struct Session {
    std::string id;
    int fd = -1;
    int target_pid = -1;
    int txn_map_fd = -1;
    std::string cgroup_path;
    std::atomic_bool running = true;
    std::thread thread;
};

std::mutex g_sessions_mutex;
std::unordered_map<std::string, std::shared_ptr<Session>> g_sessions;

void LogError(const char* message) {
    __android_log_print(ANDROID_LOG_ERROR, kTag, "%s errno=%d", message, errno);
}

int SysBpf(enum bpf_cmd cmd, union bpf_attr* attr) {
    return static_cast<int>(syscall(__NR_bpf, cmd, attr, sizeof(*attr)));
}

std::string ReadCgroupPathForPid(pid_t pid) {
    std::ifstream input("/proc/" + std::to_string(pid) + "/cgroup");
    std::string line;
    while (std::getline(input, line)) {
        if (line.rfind("0::", 0) == 0) {
            return "/sys/fs/cgroup" + line.substr(3);
        }
    }
    return "";
}

int OpenPinnedTxnMap() {
    union bpf_attr attr {};
    attr.pathname = reinterpret_cast<__u64>(kPinnedTxnMapPath);
    attr.file_flags = O_RDONLY;
    return SysBpf(BPF_OBJ_GET, &attr);
}

TxnLookupResult LookupTransactionForTid(int map_fd, uint32_t tid) {
    TxnLookupResult result;
    if (map_fd < 0) {
        result.status = "Pinned txn_map unavailable";
        return result;
    }

    union bpf_attr attr {};
    attr.map_fd = static_cast<__u32>(map_fd);
    attr.key = reinterpret_cast<__u64>(&tid);
    attr.value = reinterpret_cast<__u64>(&result.info);
    if (SysBpf(BPF_MAP_LOOKUP_AND_DELETE_ELEM, &attr) == 0) {
        result.found = true;
        result.status = "eBPF txn_map hit";
        return result;
    }
    if (errno == ENOENT) {
        result.status = "No eBPF entry for tid";
        return result;
    }

    result.status = "txn_map lookup failed";
    return result;
}

bool NotificationStillValid(const Session& session, uint64_t id) {
#ifdef SECCOMP_IOCTL_NOTIF_ID_VALID
    if (ioctl(session.fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0) {
        return true;
    }
    return errno != ENOENT;
#else
    (void)session;
    (void)id;
    return true;
#endif
}

jstring NewJavaString(JNIEnv* env, const std::string& value) {
    return env->NewStringUTF(value.c_str());
}

void DeliverNotification(const Session& session, const seccomp_notif& request,
                         const TxnLookupResult& txn) {
    JNIEnv* env = nullptr;
    bool should_detach = false;
    if (g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        if (g_vm->AttachCurrentThread(&env, nullptr) != JNI_OK) {
            return;
        }
        should_detach = true;
    }

    jstring session_id = NewJavaString(env, session.id);
    jstring cgroup_path = NewJavaString(env, session.cgroup_path);
    jstring monitor_status = NewJavaString(env, txn.status);
    jstring binder_interface = NewJavaString(env, txn.found ? txn.info.interface : "");
    jstring intent_action = NewJavaString(env, txn.found ? txn.info.intent.action : "");
    jstring intent_uri = NewJavaString(env, txn.found ? txn.info.intent.uri : "");

    env->CallStaticVoidMethod(
            g_repo_class,
            g_on_notification,
            session_id,
            static_cast<jlong>(request.id),
            static_cast<jint>(request.pid),
            static_cast<jint>(request.data.nr),
            static_cast<jlong>(request.data.args[1]),
            static_cast<jint>(session.target_pid),
            cgroup_path,
            monitor_status,
            binder_interface,
            static_cast<jint>(txn.found ? txn.info.code : 0),
            static_cast<jint>(txn.found ? txn.info.target_handle : 0),
            intent_action,
            intent_uri,
            static_cast<jboolean>(txn.found && txn.info.parcel_truncated != 0));

    env->DeleteLocalRef(session_id);
    env->DeleteLocalRef(cgroup_path);
    env->DeleteLocalRef(monitor_status);
    env->DeleteLocalRef(binder_interface);
    env->DeleteLocalRef(intent_action);
    env->DeleteLocalRef(intent_uri);

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

        if (!NotificationStillValid(*session, request.id)) {
            continue;
        }

        const TxnLookupResult txn = LookupTransactionForTid(session->txn_map_fd, request.pid);
        DeliverNotification(*session, request, txn);
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

std::string CopyJString(JNIEnv* env, jstring value) {
    const char* raw = env->GetStringUTFChars(value, nullptr);
    std::string out = raw != nullptr ? raw : "";
    if (raw != nullptr) {
        env->ReleaseStringUTFChars(value, raw);
    }
    return out;
}

}  // namespace

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_seccomp_policydaemon_SeccompNativeBridge_nativeStartListener(
        JNIEnv* env, jclass, jstring session_id_j, jint fd, jint target_pid) {
    const std::string session_id = CopyJString(env, session_id_j);
    if (session_id.empty() || fd < 0 || target_pid <= 0) {
        if (fd >= 0) {
            close(fd);
        }
        return JNI_FALSE;
    }

    auto session = std::make_shared<Session>();
    session->id = session_id;
    session->fd = fd;
    session->target_pid = target_pid;
    session->cgroup_path = ReadCgroupPathForPid(target_pid);
    session->txn_map_fd = OpenPinnedTxnMap();

    {
        std::lock_guard<std::mutex> lock(g_sessions_mutex);
        if (g_sessions.contains(session_id)) {
            if (session->txn_map_fd >= 0) {
                close(session->txn_map_fd);
            }
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

    session->running = false;
    if (session->fd >= 0) {
        close(session->fd);
        session->fd = -1;
    }
    if (session->thread.joinable()) {
        session->thread.join();
    }
    if (session->txn_map_fd >= 0) {
        close(session->txn_map_fd);
        session->txn_map_fd = -1;
    }
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_seccomp_policydaemon_SeccompNativeBridge_nativeRespond(
        JNIEnv* env, jclass, jstring session_id_j, jlong notification_id, jboolean allow,
        jint deny_errno) {
    const std::string session_id = CopyJString(env, session_id_j);

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
            "(Ljava/lang/String;JIIJILjava/lang/String;Ljava/lang/String;Ljava/lang/String;IILjava/lang/String;Ljava/lang/String;Z)V");
    if (g_on_notification == nullptr) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}
