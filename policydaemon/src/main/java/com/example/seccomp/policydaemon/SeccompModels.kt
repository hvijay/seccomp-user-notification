package com.example.seccomp.policydaemon

data class PendingRequest(
    val sessionId: String,
    val notificationId: Long,
    val pid: Int,
    val syscallNr: Int,
    val description: String,
    val ioctlCmd: Long,
    val targetPid: Int,
    val cgroupPath: String,
    val monitorStatus: String,
    val binderInterface: String,
    val binderCode: Int,
    val targetHandle: Int,
    val intentAction: String,
    val intentUri: String,
    val parcelTruncated: Boolean,
    val parsedCall: BinderCallInfo? = null,
)

data class RepositoryState(
    val activeSessionCount: Int = 0,
    val pendingRequests: List<PendingRequest> = emptyList(),
    val lastStatus: String = "No active sessions.",
)

enum class DecisionState(val code: Int) {
    PENDING(0),
    ALLOW(1),
    DENY(-1),
}
