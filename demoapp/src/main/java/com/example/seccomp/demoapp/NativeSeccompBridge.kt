package com.example.seccomp.demoapp

object NativeSeccompBridge {
    init {
        System.loadLibrary("seccomp_demo")
    }

    external fun installFilterForkAndTriggerIntent(
        action: String,
        targetPackage: String,
        targetComponent: String,
        dataUri: String,
    ): IntArray

    external fun readChildResult(readFd: Int): String

    external fun triggerChild(goWriteFd: Int)

    external fun awaitNotification(listenerFd: Int): LongArray

    external fun respondNotification(
        listenerFd: Int,
        notificationId: Long,
        allow: Boolean,
        denyErrno: Int,
    ): Boolean

    external fun closeFd(fd: Int)
}
