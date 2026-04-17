package com.example.seccomp.policydaemon

object SeccompNativeBridge {
    init {
        System.loadLibrary("seccomp_policy")
    }

    external fun nativeStartListener(sessionId: String, fd: Int): Boolean

    external fun nativeStopListener(sessionId: String)

    external fun nativeRespond(
        sessionId: String,
        notificationId: Long,
        allow: Boolean,
        denyErrno: Int,
    ): Boolean
}
