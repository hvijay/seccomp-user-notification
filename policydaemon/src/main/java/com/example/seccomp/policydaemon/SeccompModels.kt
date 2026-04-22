package com.example.seccomp.policydaemon

const val OP_KIND_UNKNOWN = 0
const val OP_KIND_BINDER = 1
const val OP_KIND_FILE_OPEN = 2
const val OP_KIND_EXEC = 3

data class PendingRequest(
    val sessionId: String,
    val notificationId: Long,
    val pid: Int,
    val syscallNr: Int,
    val operationKind: Int,
    val description: String,
    val ioctlCmd: Long,
    val targetPid: Int,
    val cgroupPath: String,
    val monitorStatus: String,
    val callingPackage: String,
    val binderInterface: String,
    val binderCode: Int,
    val targetHandle: Int,
    val intentAction: String,
    val intentUri: String,
    val filePath: String,
    val execArgv: String,
    val openFlags: Int,
    val openMode: Int,
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
