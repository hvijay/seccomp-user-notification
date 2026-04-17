package com.example.seccomp.policydaemon

import android.app.Application

class PolicyDaemonApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        SeccompRepository.initialize(this)
    }
}
