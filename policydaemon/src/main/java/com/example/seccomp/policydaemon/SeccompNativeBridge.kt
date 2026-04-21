package com.example.seccomp.policydaemon

object SeccompNativeBridge {
    init {
        System.loadLibrary("seccomp_policy")
    }

    external fun nativeStartMonitoring(
        sessionId: String,
        targetPid: Int,
    ): Boolean

    external fun nativeStopListener(sessionId: String)
}
