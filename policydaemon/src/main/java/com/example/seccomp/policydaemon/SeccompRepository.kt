package com.example.seccomp.policydaemon

import android.content.Context
import android.os.ParcelFileDescriptor
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

object SeccompRepository {
    private lateinit var appContext: Context

    private val sessionDescriptions = linkedMapOf<String, String>()
    private val sessionTargetPids = linkedMapOf<String, Int>()
    private val pendingRequests = linkedMapOf<String, PendingRequest>()
    private val decisions = linkedMapOf<String, DecisionState>()

    private val _state = MutableStateFlow(RepositoryState())
    val state: StateFlow<RepositoryState> = _state.asStateFlow()

    fun initialize(context: Context) {
        appContext = context.applicationContext
    }

    @Synchronized
    fun registerSession(sessionId: String, fd: Int, description: String, targetPid: Int): Boolean {
        if (!::appContext.isInitialized) {
            return false
        }
        if (sessionDescriptions.containsKey(sessionId)) {
            return false
        }
        clearSessionsLocked()
        runCatching { ParcelFileDescriptor.adoptFd(fd).close() }
        val ok = SeccompNativeBridge.nativeStartMonitoring(sessionId, targetPid)
        if (!ok) {
            return false
        }
        sessionDescriptions[sessionId] = description
        sessionTargetPids[sessionId] = targetPid
        publish("Listening for Binder seccomp notifications from pid=$targetPid. Active sessions=${sessionDescriptions.size}")
        return true
    }

    @Synchronized
    fun unregisterSession(sessionId: String) {
        SeccompNativeBridge.nativeStopListener(sessionId)
        sessionDescriptions.remove(sessionId)
        sessionTargetPids.remove(sessionId)
        pendingRequests.entries.removeAll { it.value.sessionId == sessionId }
        decisions.keys.removeAll { it.startsWith("$sessionId:") }
        publish("Session removed: $sessionId")
    }

    @Synchronized
    fun publishPendingRequest(
        sessionId: String,
        notificationId: Long,
        pid: Int,
        syscallNr: Int,
        ioctlCmd: Long,
    ) {
        val description = sessionDescriptions[sessionId] ?: "Unknown session"
        val key = "$sessionId:$notificationId"
        val targetPid = sessionTargetPids[sessionId] ?: -1
        pendingRequests[key] = PendingRequest(
            sessionId = sessionId,
            notificationId = notificationId,
            pid = pid,
            syscallNr = syscallNr,
            description = description,
            ioctlCmd = ioctlCmd,
            targetPid = targetPid,
            cgroupPath = "",
            monitorStatus = "seccomp user-notify",
            binderInterface = "",
            binderCode = 0,
            targetHandle = 0,
            intentAction = "",
            intentUri = "",
            parcelTruncated = false,
        )
        publish("Pending Binder request from tid=$pid (target pid=$targetPid). Tap allow or deny.")
    }

    @Synchronized
    fun allow(request: PendingRequest): Boolean {
        decisions["${request.sessionId}:${request.notificationId}"] = DecisionState.ALLOW
        pendingRequests.remove("${request.sessionId}:${request.notificationId}")
        publish("Allowed notification ${request.notificationId} for pid=${request.pid}")
        return true
    }

    @Synchronized
    fun deny(request: PendingRequest): Boolean {
        decisions["${request.sessionId}:${request.notificationId}"] = DecisionState.DENY
        pendingRequests.remove("${request.sessionId}:${request.notificationId}")
        publish("Denied notification ${request.notificationId} for pid=${request.pid}")
        return true
    }

    @Synchronized
    fun respondToPendingRequest(allow: Boolean, notificationKey: String?): Boolean {
        val request = when {
            notificationKey != null -> pendingRequests[notificationKey]
            else -> pendingRequests.values.firstOrNull()
        } ?: run {
            publish("No pending request matched key=${notificationKey ?: "<first>"}")
            return false
        }
        return if (allow) {
            allow(request)
        } else {
            deny(request)
        }
    }

    @Synchronized
    fun getDecision(sessionId: String, notificationId: Long): Int {
        val key = "$sessionId:$notificationId"
        return (decisions.remove(key) ?: DecisionState.PENDING).code
    }

    private fun clearSessionsLocked() {
        sessionDescriptions.keys.toList().forEach { SeccompNativeBridge.nativeStopListener(it) }
        sessionDescriptions.clear()
        sessionTargetPids.clear()
        pendingRequests.clear()
        decisions.clear()
    }

    @Synchronized
    private fun publish(status: String) {
        DebugStateStore.record(status)
        _state.value = RepositoryState(
            activeSessionCount = sessionDescriptions.size,
            pendingRequests = pendingRequests.values.toList(),
            lastStatus = status,
        )
    }
}
