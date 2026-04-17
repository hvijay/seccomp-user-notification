package com.example.seccomp.demoapp

object NativeSeccompBridge {
    init {
        System.loadLibrary("seccomp_demo")
    }

    external fun installFilterForkAndTrigger(path: String): IntArray

    external fun readChildResult(readFd: Int): String
}
