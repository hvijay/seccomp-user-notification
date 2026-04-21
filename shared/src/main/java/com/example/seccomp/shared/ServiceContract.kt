package com.example.seccomp.shared

object ServiceContract {
    const val DEMO_PACKAGE = "com.example.seccomp.demoapp"
    const val DEMO_ACTIVITY = "com.example.seccomp.demoapp.MainActivity"
    const val DEMO_NATIVE_ACTION = "android.intent.action.VIEW"
    const val DEMO_NATIVE_URI = "https://example.com/"
    const val DEMO_RUN_ACTION = "com.example.seccomp.demoapp.action.RUN_DEMO"
    const val DAEMON_PACKAGE = "com.example.seccomp.policydaemon"
    const val DAEMON_ACTIVITY = "com.example.seccomp.policydaemon.MainActivity"
    const val DAEMON_SERVICE = "com.example.seccomp.policydaemon.PolicyDaemonService"
    const val DAEMON_BIND_ACTION = "com.example.seccomp.policydaemon.BIND_POLICY_DAEMON"
    const val DAEMON_COMMAND_ACTION = "com.example.seccomp.policydaemon.action.COMMAND"
    const val EXTRA_NOTIFICATION_KEY = "notification_key"
    const val EXTRA_DECISION = "decision"
    const val DECISION_ALLOW = "allow"
    const val DECISION_DENY = "deny"
    const val NOTIFICATION_CHANNEL_ID = "policy-daemon"
}
