package com.example.seccomp.policydaemon

import android.content.Context
import org.json.JSONArray

object DebugStateStore {
    private const val PREFS_NAME = "debug_state"
    private const val KEY_LAST_STATUS = "last_status"
    private const val KEY_EVENTS = "events"
    private const val MAX_EVENTS = 80

    private lateinit var appContext: Context

    fun initialize(context: Context) {
        appContext = context.applicationContext
    }

    @Synchronized
    fun record(status: String) {
        if (!::appContext.isInitialized) {
            return
        }
        val prefs = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val events = JSONArray(prefs.getString(KEY_EVENTS, "[]") ?: "[]")
        events.put(status)
        while (events.length() > MAX_EVENTS) {
            events.remove(0)
        }
        prefs.edit()
            .putString(KEY_LAST_STATUS, status)
            .putString(KEY_EVENTS, events.toString())
            .apply()
    }

    @Synchronized
    fun snapshot(repositoryState: RepositoryState): PolicyDebugSnapshot {
        if (!::appContext.isInitialized) {
            return PolicyDebugSnapshot("", emptyList(), 0, emptyList())
        }
        val prefs = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val eventsJson = JSONArray(prefs.getString(KEY_EVENTS, "[]") ?: "[]")
        val events = buildList(eventsJson.length()) {
            for (index in 0 until eventsJson.length()) {
                add(eventsJson.optString(index))
            }
        }
        return PolicyDebugSnapshot(
            lastStatus = prefs.getString(KEY_LAST_STATUS, "") ?: "",
            events = events,
            activeSessionCount = repositoryState.activeSessionCount,
            pendingRequests = repositoryState.pendingRequests,
        )
    }
}

data class PolicyDebugSnapshot(
    val lastStatus: String,
    val events: List<String>,
    val activeSessionCount: Int,
    val pendingRequests: List<PendingRequest>,
)
