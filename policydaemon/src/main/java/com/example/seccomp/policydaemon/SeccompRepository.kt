package com.example.seccomp.policydaemon

import android.content.Context
import android.system.OsConstants
import android.os.ParcelFileDescriptor
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

object SeccompRepository {
    private lateinit var appContext: Context

    private val sessionDescriptions = linkedMapOf<String, String>()
    private val pendingRequests = linkedMapOf<String, PendingRequest>()

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
        val ok = SeccompNativeBridge.nativeStartListener(sessionId, fd, targetPid)
        if (!ok) {
            runCatching { ParcelFileDescriptor.adoptFd(fd).close() }
            return false
        }
        sessionDescriptions[sessionId] = description
        publish("Listening for Binder seccomp notifications from pid=$targetPid. Active sessions=${sessionDescriptions.size}")
        return true
    }

    @Synchronized
    fun unregisterSession(sessionId: String) {
        SeccompNativeBridge.nativeStopListener(sessionId)
        sessionDescriptions.remove(sessionId)
        pendingRequests.entries.removeAll { it.value.sessionId == sessionId }
        publish("Session removed: $sessionId")
    }

    @JvmStatic
    @Synchronized
    fun onNativeNotification(
        sessionId: String,
        notificationId: Long,
        pid: Int,
        syscallNr: Int,
        ioctlCmd: Long,
        targetPid: Int,
        cgroupPath: String,
        monitorStatus: String,
        binderInterface: String,
        binderCode: Int,
        targetHandle: Int,
        intentAction: String,
        intentUri: String,
        parcelTruncated: Boolean,
    ) {
        val description = sessionDescriptions[sessionId] ?: "Unknown session"
        val key = "$sessionId:$notificationId"
        pendingRequests[key] = PendingRequest(
            sessionId = sessionId,
            notificationId = notificationId,
            pid = pid,
            syscallNr = syscallNr,
            description = description,
            ioctlCmd = ioctlCmd,
            targetPid = targetPid,
            cgroupPath = cgroupPath,
            monitorStatus = monitorStatus,
            binderInterface = binderInterface,
            binderCode = binderCode,
            targetHandle = targetHandle,
            intentAction = intentAction,
            intentUri = intentUri,
            parcelTruncated = parcelTruncated,
        )
        publish("Pending Binder request from tid=$pid (target pid=$targetPid). Tap allow or deny.")
    }

    @Synchronized
    fun allow(request: PendingRequest): Boolean {
        val ok = SeccompNativeBridge.nativeRespond(
            request.sessionId,
            request.notificationId,
            true,
            0,
        )
        if (ok) {
            pendingRequests.remove("${request.sessionId}:${request.notificationId}")
            publish("Allowed notification ${request.notificationId} for pid=${request.pid}")
        }
        return ok
    }

    @Synchronized
    fun deny(request: PendingRequest): Boolean {
        val ok = SeccompNativeBridge.nativeRespond(
            request.sessionId,
            request.notificationId,
            false,
            OsConstants.EPERM,
        )
        if (ok) {
            pendingRequests.remove("${request.sessionId}:${request.notificationId}")
            publish("Denied notification ${request.notificationId} for pid=${request.pid}")
        }
        return ok
    }

    @Synchronized
    private fun publish(status: String) {
        _state.value = RepositoryState(
            activeSessionCount = sessionDescriptions.size,
            pendingRequests = pendingRequests.values.toList(),
            lastStatus = status,
        )
    }
}
