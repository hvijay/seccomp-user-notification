package com.example.seccomp.demoapp

import android.content.Context
import org.json.JSONArray

object DebugStateStore {
    private const val PREFS_NAME = "debug_state"
    private const val KEY_LAST_STATUS = "last_status"
    private const val KEY_EVENTS = "events"
    private const val MAX_EVENTS = 40

    private lateinit var appContext: Context

    fun initialize(context: Context) {
        appContext = context.applicationContext
    }

    @Synchronized
    fun updateStatus(status: String) {
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
    fun snapshot(): DemoDebugSnapshot {
        if (!::appContext.isInitialized) {
            return DemoDebugSnapshot("", emptyList())
        }
        val prefs = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val eventsJson = JSONArray(prefs.getString(KEY_EVENTS, "[]") ?: "[]")
        val events = buildList(eventsJson.length()) {
            for (index in 0 until eventsJson.length()) {
                add(eventsJson.optString(index))
            }
        }
        return DemoDebugSnapshot(
            lastStatus = prefs.getString(KEY_LAST_STATUS, "") ?: "",
            events = events,
        )
    }
}

data class DemoDebugSnapshot(
    val lastStatus: String,
    val events: List<String>,
)
