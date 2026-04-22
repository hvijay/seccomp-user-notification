package com.example.seccomp.policydaemon

import android.app.ActivityManager
import android.content.Context
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

object SeccompRepository {
    private const val TAG = "SeccompRepository"
    private lateinit var appContext: Context

    private val sessionDescriptions = linkedMapOf<String, String>()
    private val sessionTargetPids = linkedMapOf<String, Int>()
    private val sessionCallerPackages = linkedMapOf<String, String>()
    private val pendingRequests = linkedMapOf<String, PendingRequest>()
    private val decisions = linkedMapOf<String, DecisionState>()

    private val _state = MutableStateFlow(RepositoryState())
    val state: StateFlow<RepositoryState> = _state.asStateFlow()

    fun initialize(context: Context) {
        appContext = context.applicationContext
    }

    @Synchronized
    fun registerSession(
        sessionId: String,
        fd: Int,
        description: String,
        targetPid: Int,
        callerPackage: String,
    ): Boolean {
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
        sessionCallerPackages[sessionId] = callerPackage
        publish("Listening for seccomp notifications from pid=$targetPid. Active sessions=${sessionDescriptions.size}")
        return true
    }

    @Synchronized
    fun unregisterSession(sessionId: String) {
        SeccompNativeBridge.nativeStopListener(sessionId)
        sessionDescriptions.remove(sessionId)
        sessionTargetPids.remove(sessionId)
        sessionCallerPackages.remove(sessionId)
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
        sessionCallerPackages.clear()
        pendingRequests.clear()
        decisions.clear()
    }

    @Synchronized
    fun refreshPendingRequests() {
        val refreshed = linkedMapOf<String, PendingRequest>()
        sessionDescriptions.forEach { (sessionId, description) ->
            val targetPid = sessionTargetPids[sessionId] ?: -1
            val raw = SeccompNativeBridge.nativeGetPendingRequest(sessionId) ?: return@forEach

            // Indices 0-12 are String metadata; 13 is byte[] parcel; 14 is String byte count.
            fun strOrNull(idx: Int): String? = raw.getOrNull(idx) as? String

            // notification_id is uint64; parse via ULong to avoid overflow on high-bit values.
            val notificationId = strOrNull(0)?.toULongOrNull()?.toLong() ?: return@forEach
            val pid = strOrNull(1)?.toIntOrNull() ?: return@forEach
            val syscallNr = strOrNull(2)?.toIntOrNull() ?: return@forEach
            val operationKind = strOrNull(3)?.toIntOrNull() ?: OP_KIND_UNKNOWN
            val ioctlCmd = strOrNull(4)?.toLongOrNull() ?: 0L
            val binderCode = strOrNull(5)?.toIntOrNull() ?: 0
            val targetHandle = strOrNull(6)?.toIntOrNull() ?: 0
            val parcelTruncated = strOrNull(7)?.toBooleanStrictOrNull() ?: false
            val openFlags = strOrNull(8)?.toIntOrNull() ?: 0
            val openMode = strOrNull(9)?.toIntOrNull() ?: 0
            val filePath = strOrNull(10).orEmpty()
            val execArgv = strOrNull(11).orEmpty()
            val parcelBytes = raw.getOrNull(13) as? ByteArray
            val capturedBytes = strOrNull(14)?.toIntOrNull() ?: 0

            // Decode exclusively in policydaemon with android.os.Parcel.
            val parsedCall = if (operationKind == OP_KIND_BINDER) parcelBytes?.let {
                BinderParcelDecoder.decode(
                    rawParcel = it,
                    capturedBytes = capturedBytes,
                    txnCode = binderCode,
                    truncated = parcelTruncated,
                )
            } else null
            if (parsedCall != null) {
                Log.d(
                    TAG,
                    "pending parsed summary=${parsedCall.summary()} parseError=${parsedCall.parseError}",
                )
            }
            val parsedIntent = parsedCall?.args
                ?.filterIsInstance<BinderArg.IntentValue>()
                ?.firstOrNull()?.intent
            val parsedUri = parsedCall?.args
                ?.filterIsInstance<BinderArg.UriValue>()
                ?.firstOrNull()?.value
            val callingPackage = sessionCallerPackages[sessionId]
                ?: resolveCallingPackage(pid)
                ?: parsedCall?.args
                    ?.filterIsInstance<BinderArg.StringValue>()
                    ?.firstOrNull { it.name == "callingPackage" || it.name == "callingPkg" }
                    ?.value
                .orEmpty()
            val key = "$sessionId:$notificationId"
            refreshed[key] = PendingRequest(
                sessionId = sessionId,
                notificationId = notificationId,
                pid = pid,
                syscallNr = syscallNr,
                operationKind = operationKind,
                description = description,
                ioctlCmd = ioctlCmd,
                targetPid = targetPid,
                cgroupPath = "",
                monitorStatus = "seccomp user-notify",
                callingPackage = callingPackage,
                binderInterface = parsedCall?.interfaceDescriptor.orEmpty(),
                binderCode = binderCode,
                targetHandle = targetHandle,
                intentAction = parsedIntent?.action.orEmpty(),
                intentUri = (parsedIntent?.data ?: parsedUri)?.toString().orEmpty(),
                filePath = filePath,
                execArgv = execArgv,
                openFlags = openFlags,
                openMode = openMode,
                parcelTruncated = parcelTruncated,
                parsedCall = parsedCall,
            )
        }
        if (refreshed != pendingRequests) {
            pendingRequests.clear()
            pendingRequests.putAll(refreshed)
            val status = if (pendingRequests.isEmpty()) {
                "Listening for seccomp notifications. Active sessions=${sessionDescriptions.size}"
            } else {
                val first = pendingRequests.values.first()
                val kind = when (first.operationKind) {
                    OP_KIND_FILE_OPEN -> "file operation"
                    OP_KIND_EXEC -> "program execution"
                    else -> "Binder request"
                }
                "Pending $kind from tid=${first.pid} (target pid=${first.targetPid}). Tap allow or deny."
            }
            publish(status)
        }
    }

    private fun resolveCallingPackage(pid: Int): String? {
        val am = appContext.getSystemService(ActivityManager::class.java) ?: return null
        val process = am.runningAppProcesses?.firstOrNull { it.pid == pid } ?: return null
        return process.pkgList?.firstOrNull() ?: process.processName
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
