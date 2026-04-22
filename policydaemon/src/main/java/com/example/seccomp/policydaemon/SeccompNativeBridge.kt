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

    // Returns Object[9]: indices 0-6 are String transport metadata, 7 is
    // ByteArray of raw parcel data (may be null if nothing was captured), and
    // 8 is String with the captured byte count.
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
