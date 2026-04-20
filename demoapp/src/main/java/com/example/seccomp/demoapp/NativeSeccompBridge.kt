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
}
