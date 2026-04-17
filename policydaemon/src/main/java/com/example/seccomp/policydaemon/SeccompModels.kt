package com.example.seccomp.policydaemon

data class PendingRequest(
    val sessionId: String,
    val notificationId: Long,
    val pid: Int,
    val syscallNr: Int,
    val description: String,
)

data class RepositoryState(
    val activeSessionCount: Int = 0,
    val pendingRequests: List<PendingRequest> = emptyList(),
    val lastStatus: String = "No active sessions.",
)
