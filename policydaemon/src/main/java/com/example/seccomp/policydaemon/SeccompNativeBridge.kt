package com.example.seccomp.policydaemon

object SeccompNativeBridge {
    init {
        System.loadLibrary("seccomp_policy")
    }

    external fun nativeRegisterSession(
        sessionId: String,
        targetPid: Int,
        listenerFd: Int,
    ): Boolean

    // Returns Object[15]: transport metadata, optional raw parcel bytes, and
    // syscall-specific details for openat/execve-like operations.
    external fun nativeGetPendingRequest(
        sessionId: String,
    ): Array<Any?>?

    external fun nativeRespondToPendingRequest(
        sessionId: String,
        notificationId: Long,
        allow: Boolean,
    ): Boolean

    external fun nativeStopListener(sessionId: String)
}
