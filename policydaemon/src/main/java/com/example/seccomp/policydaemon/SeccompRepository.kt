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
        val ok = SeccompNativeBridge.nativeRegisterSession(sessionId, targetPid, fd)
        runCatching { ParcelFileDescriptor.adoptFd(fd).close() }
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
    fun allow(request: PendingRequest): Boolean {
        val ok = SeccompNativeBridge.nativeRespondToPendingRequest(
            request.sessionId,
            request.notificationId,
            true,
        )
        if (!ok) {
            publish("Failed to allow notification ${request.notificationId} for pid=${request.pid}")
            return false
        }
        pendingRequests.remove("${request.sessionId}:${request.notificationId}")
        publish("Allowed notification ${request.notificationId} for pid=${request.pid}")
        return true
    }

    @Synchronized
    fun deny(request: PendingRequest): Boolean {
        val ok = SeccompNativeBridge.nativeRespondToPendingRequest(
            request.sessionId,
            request.notificationId,
            false,
        )
        if (!ok) {
            publish("Failed to deny notification ${request.notificationId} for pid=${request.pid}")
            return false
        }
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

    private fun clearSessionsLocked() {
        sessionDescriptions.keys.toList().forEach { SeccompNativeBridge.nativeStopListener(it) }
        sessionDescriptions.clear()
        sessionTargetPids.clear()
        pendingRequests.clear()
        decisions.clear()
    }

    @Synchronized
    fun refreshPendingRequests() {
        val refreshed = linkedMapOf<String, PendingRequest>()
        sessionDescriptions.forEach { (sessionId, description) ->
            val targetPid = sessionTargetPids[sessionId] ?: -1
            val parsed = SeccompNativeBridge.nativeGetPendingRequest(sessionId) ?: return@forEach
            val notificationId = parsed.getOrNull(0)?.toLongOrNull() ?: return@forEach
            val pid = parsed.getOrNull(1)?.toIntOrNull() ?: return@forEach
            val syscallNr = parsed.getOrNull(2)?.toIntOrNull() ?: return@forEach
            val ioctlCmd = parsed.getOrNull(3)?.toLongOrNull() ?: return@forEach
            val key = "$sessionId:$notificationId"
            refreshed[key] = PendingRequest(
                sessionId = sessionId,
                notificationId = notificationId,
                pid = pid,
                syscallNr = syscallNr,
                description = description,
                ioctlCmd = ioctlCmd,
                targetPid = targetPid,
                cgroupPath = "",
                monitorStatus = "seccomp user-notify",
                binderInterface = parsed.getOrNull(4).orEmpty(),
                binderCode = parsed.getOrNull(5)?.toIntOrNull() ?: 0,
                targetHandle = parsed.getOrNull(6)?.toIntOrNull() ?: 0,
                intentAction = parsed.getOrNull(7).orEmpty(),
                intentUri = parsed.getOrNull(8).orEmpty(),
                parcelTruncated = parsed.getOrNull(9)?.toBooleanStrictOrNull() ?: false,
            )
        }
        if (refreshed != pendingRequests) {
            pendingRequests.clear()
            pendingRequests.putAll(refreshed)
            val status = if (pendingRequests.isEmpty()) {
                "Listening for Binder seccomp notifications. Active sessions=${sessionDescriptions.size}"
            } else {
                val first = pendingRequests.values.first()
                "Pending Binder request from tid=${first.pid} (target pid=${first.targetPid}). Tap allow or deny."
            }
            publish(status)
        }
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
