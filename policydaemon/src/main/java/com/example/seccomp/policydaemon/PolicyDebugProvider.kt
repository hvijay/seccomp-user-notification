package com.example.seccomp.policydaemon

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri

class PolicyDebugProvider : ContentProvider() {
    override fun onCreate(): Boolean {
        context?.let {
            DebugStateStore.initialize(it)
            SeccompRepository.initialize(it)
        }
        return true
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor {
        val snapshot = DebugStateStore.snapshot(SeccompRepository.state.value)
        return when (uri.lastPathSegment) {
            "status" -> MatrixCursor(arrayOf("last_status", "active_sessions", "pending_requests")).apply {
                addRow(
                    arrayOf(
                        snapshot.lastStatus,
                        snapshot.activeSessionCount,
                        snapshot.pendingRequests.size,
                    ),
                )
            }

            "events" -> MatrixCursor(arrayOf("idx", "message")).apply {
                snapshot.events.forEachIndexed { index, message ->
                    addRow(arrayOf(index, message))
                }
            }

            "pending" -> MatrixCursor(
                arrayOf(
                    "notification_id",
                    "tid",
                    "calling_package",
                    "operation_kind",
                    "monitor_status",
                    "file_path",
                    "open_flags",
                    "open_mode",
                    "exec_argv",
                    "binder_interface",
                    "binder_code",
                    "intent_action",
                    "intent_uri",
                    "parsed_summary",
                    "parse_error",
                ),
            ).apply {
                snapshot.pendingRequests.forEach { request ->
                    addRow(
                        arrayOf(
                            request.notificationId,
                            request.pid,
                            request.callingPackage,
                            request.operationKind,
                            request.monitorStatus,
                            request.filePath,
                            request.openFlags,
                            request.openMode,
                            request.execArgv,
                            request.binderInterface,
                            request.binderCode,
                            request.intentAction,
                            request.intentUri,
                            request.parsedCall?.summary().orEmpty(),
                            request.parsedCall?.parseError.orEmpty(),
                        ),
                    )
                }
            }

            else -> MatrixCursor(arrayOf("error")).apply {
                addRow(arrayOf("Unknown path: ${uri.lastPathSegment}"))
            }
        }
    }

    override fun getType(uri: Uri): String = "vnd.android.cursor.item/vnd.${uri.authority}.${uri.lastPathSegment}"

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = 0
}
