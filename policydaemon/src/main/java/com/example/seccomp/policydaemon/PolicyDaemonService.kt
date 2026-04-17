package com.example.seccomp.policydaemon

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.example.seccomp.shared.ISeccompPolicyDaemon
import com.example.seccomp.shared.ServiceContract
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

class PolicyDaemonService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    private val binder = object : ISeccompPolicyDaemon.Stub() {
        override fun registerSession(
            sessionId: String,
            listenerFd: android.os.ParcelFileDescriptor,
            description: String,
        ): Boolean {
            val rawFd = listenerFd.detachFd()
            return SeccompRepository.registerSession(sessionId, rawFd, description)
        }

        override fun unregisterSession(sessionId: String) {
            SeccompRepository.unregisterSession(sessionId)
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(1001, buildNotification("Policy daemon is idle."))
        scope.launch {
            SeccompRepository.state.collectLatest { state ->
                val summary = if (state.pendingRequests.isEmpty()) {
                    state.lastStatus
                } else {
                    "Pending decisions=${state.pendingRequests.size}, active sessions=${state.activeSessionCount}"
                }
                getSystemService(NotificationManager::class.java)
                    .notify(1001, buildNotification(summary))
            }
        }
    }

    override fun onBind(intent: Intent): IBinder {
        return binder
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return START_STICKY
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun buildNotification(text: String): Notification {
        val contentIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, ServiceContract.NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_secure)
            .setContentTitle("Seccomp policy daemon")
            .setContentText(text)
            .setContentIntent(contentIntent)
            .setOngoing(true)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }
        val channel = NotificationChannel(
            ServiceContract.NOTIFICATION_CHANNEL_ID,
            "Policy daemon",
            NotificationManager.IMPORTANCE_HIGH,
        )
        channel.description = "Seccomp user-notify daemon status"
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }
}
