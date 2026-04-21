package com.example.seccomp.demoapp

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri

class DemoDebugProvider : ContentProvider() {
    override fun onCreate(): Boolean {
        context?.let { DebugStateStore.initialize(it) }
        return true
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor {
        val snapshot = DebugStateStore.snapshot()
        return when (uri.lastPathSegment) {
            "status" -> MatrixCursor(arrayOf("last_status")).apply {
                addRow(arrayOf(snapshot.lastStatus))
            }

            "events" -> MatrixCursor(arrayOf("idx", "message")).apply {
                snapshot.events.forEachIndexed { index, message ->
                    addRow(arrayOf(index, message))
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
