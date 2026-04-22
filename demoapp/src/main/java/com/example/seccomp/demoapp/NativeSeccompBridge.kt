package com.example.seccomp.demoapp

object NativeSeccompBridge {
    init {
        System.loadLibrary("seccomp_demo")
    }

    external fun installFilterForkAndTriggerTransaction(
        transactionCode: Int,
        rawParcel: ByteArray,
        outcomeLabel: String,
    ): IntArray

    external fun installFilterForkAndReadFile(
        filePath: String,
        openFlags: Int,
        outcomeLabel: String,
    ): IntArray

    external fun installFilterForkAndExec(
        executablePath: String,
        argv: Array<String>,
        outcomeLabel: String,
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
