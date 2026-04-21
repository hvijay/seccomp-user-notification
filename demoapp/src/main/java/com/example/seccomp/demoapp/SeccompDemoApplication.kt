package com.example.seccomp.demoapp

import android.app.Application

class SeccompDemoApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        DebugStateStore.initialize(this)
    }
}
