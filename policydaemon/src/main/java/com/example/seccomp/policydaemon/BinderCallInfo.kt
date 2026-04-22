package com.example.seccomp.policydaemon

import android.content.Intent
import android.net.Uri

/** High-level semantics extracted from a raw Binder transaction parcel. */
data class BinderCallInfo(
    val interfaceDescriptor: String,
    val methodName: String,
    val transactionCode: Int,
    val args: List<BinderArg>,
    val parseError: String? = null,
    val truncated: Boolean = false,
) {
    /** One-line summary for display in the allow/deny UI. */
    fun summary(): String = buildString {
        val iface = interfaceDescriptor.substringAfterLast('.')
        append("$iface.$methodName")
        if (args.isNotEmpty()) {
            append("(")
            append(args.take(4).joinToString(", ") { it.summary() })
            if (args.size > 4) append(", …")
            append(")")
        }
        if (truncated) append(" [parcel truncated]")
        if (parseError != null) append(" [$parseError]")
    }
}

/** A single parsed argument from a Binder transaction. */
sealed class BinderArg(val name: String) {
    abstract fun summary(): String

    class IntValue(name: String, val value: Int) : BinderArg(name) {
        override fun summary() = "$name=$value"
    }

    class StringValue(name: String, val value: String?) : BinderArg(name) {
        override fun summary() = if (value != null) "$name=\"$value\"" else "$name=null"
    }

    class UriValue(name: String, val value: Uri?) : BinderArg(name) {
        override fun summary() = if (value != null) "$name=$value" else "$name=null"
    }

    class IntentValue(name: String, val intent: Intent?) : BinderArg(name) {
        override fun summary(): String {
            intent ?: return "$name=null"
            return buildString {
                append("$name={")
                intent.action?.let { append("action=$it") }
                intent.data?.let { append(" data=$it") }
                intent.`package`?.let { append(" pkg=$it") }
                intent.component?.let {
                    append(" cmp=${it.className.substringAfterLast('.')}")
                }
                if (!intent.categories.isNullOrEmpty()) {
                    append(" cats=${intent.categories!!.joinToString(",")}")
                }
                append("}")
            }
        }
    }
}
