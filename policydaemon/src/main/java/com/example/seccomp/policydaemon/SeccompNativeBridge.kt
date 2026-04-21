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

    external fun nativeGetPendingRequest(
        sessionId: String,
    ): Array<String>?

    external fun nativeRespondToPendingRequest(
        sessionId: String,
        notificationId: Long,
        allow: Boolean,
    ): Boolean

    external fun nativeStopListener(sessionId: String)
}
