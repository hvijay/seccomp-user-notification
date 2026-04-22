package com.example.seccomp.policydaemon

import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.example.seccomp.policydaemon.databinding.ItemRequestBinding

class PendingRequestAdapter(
    private val onAllow: (PendingRequest) -> Unit,
    private val onDeny: (PendingRequest) -> Unit,
) : ListAdapter<PendingRequest, PendingRequestAdapter.RequestViewHolder>(DiffCallback) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RequestViewHolder {
        val binding = ItemRequestBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false,
        )
        return RequestViewHolder(binding, onAllow, onDeny)
    }

    override fun onBindViewHolder(holder: RequestViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    class RequestViewHolder(
        private val binding: ItemRequestBinding,
        private val onAllow: (PendingRequest) -> Unit,
        private val onDeny: (PendingRequest) -> Unit,
    ) : RecyclerView.ViewHolder(binding.root) {
        fun bind(item: PendingRequest) {
            val header = buildString {
                append("tid=${item.pid}, syscall=${item.syscallNr}")
                if (item.binderCode != 0) append(", code=${item.binderCode}")
            }
            val body = SpannableStringBuilder().apply {

                // ── libbinder-decoded call (primary display) ──────────────────
                val call = item.parsedCall
                if (call != null) {
                    appendHighlightedLine("Call", call.summary())

                    call.args.filterIsInstance<BinderArg.IntentValue>().firstOrNull()?.intent
                        ?.let { intent ->
                            intent.action?.let { appendNormalLine("  action", it) }
                            intent.data?.let { appendNormalLine("  data", it.toString()) }
                            intent.`package`?.let { appendNormalLine("  package", it) }
                            intent.component?.let {
                                appendNormalLine("  component", it.flattenToShortString())
                            }
                            if (!intent.categories.isNullOrEmpty()) {
                                appendNormalLine("  categories",
                                    intent.categories!!.joinToString(", "))
                            }
                            intentWarnings(intent).forEach { warning ->
                                appendHighlightedLine("Meaning", warning)
                            }
                        }

                    call.args.filterIsInstance<BinderArg.StringValue>()
                        .filter { it.value != null }
                        .forEach { arg ->
                            appendNormalLine("  ${arg.name}", arg.value!!)
                        }
                    call.args.filterIsInstance<BinderArg.UriValue>().forEach { arg ->
                        appendNormalLine("  ${arg.name}", arg.value?.toString() ?: "null")
                        uriWarnings(call, arg.value).forEach { warning ->
                            appendHighlightedLine("Meaning", warning)
                        }
                    }
                } else {
                    if (item.intentAction.isNotEmpty() || item.intentUri.isNotEmpty()) {
                        appendHighlightedLine(
                            "Intent",
                            buildString {
                                if (item.intentAction.isNotEmpty()) append(item.intentAction)
                                if (item.intentUri.isNotEmpty()) {
                                    if (isNotEmpty()) append(" -> ")
                                    append(item.intentUri)
                                }
                            },
                        )
                        val fallbackIntent = Intent().apply {
                            if (item.intentAction.isNotEmpty()) action = item.intentAction
                            if (item.intentUri.isNotEmpty()) data = Uri.parse(item.intentUri)
                        }
                        intentWarnings(fallbackIntent).forEach { warning ->
                            appendHighlightedLine("Meaning", warning)
                        }
                    }
                }

                // ── Metadata ──────────────────────────────────────────────────
                appendNormalLine("notificationId", item.notificationId.toString())
                appendNormalLine("ioctlCmd", "0x${item.ioctlCmd.toString(16)}")
                appendNormalLine("monitor", item.monitorStatus)
                if (item.cgroupPath.isNotEmpty()) {
                    appendNormalLine("cgroup", item.cgroupPath)
                }
                if (item.binderInterface.isNotEmpty()) {
                    appendNormalLine("interface", item.binderInterface)
                }
                if (item.targetHandle != 0) {
                    appendNormalLine("targetHandle", item.targetHandle.toString())
                }
                if (item.parcelTruncated) {
                    appendNormalLine("parcelTruncated", "true")
                }
                while (endsWith("\n")) {
                    delete(length - 1, length)
                }
            }
            binding.titleText.text = header
            binding.bodyText.text = body
            binding.allowButton.setOnClickListener { onAllow(item) }
            binding.denyButton.setOnClickListener { onDeny(item) }
        }

        private fun SpannableStringBuilder.appendNormalLine(label: String, value: String) {
            append(label)
            append("=")
            append(value)
            append("\n")
        }

        private fun SpannableStringBuilder.appendHighlightedLine(label: String, value: String) {
            val line = "$label: $value\n"
            val start = length
            append(line)
            setSpan(StyleSpan(Typeface.BOLD), start, start + line.length - 1, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            setSpan(
                ForegroundColorSpan(Color.parseColor("#FF5252")),
                start,
                start + line.length - 1,
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE,
            )
        }

        private fun intentWarnings(intent: Intent): List<String> {
            val out = linkedSetOf<String>()
            when (intent.action) {
                Intent.ACTION_VIEW -> out += when (intent.data?.scheme) {
                    "content" -> "This would open content exposed by another app."
                    "tel" -> "This would open the dialer for a phone number."
                    "geo" -> "This would open a maps location or search."
                    "mailto" -> "This would open an email compose or mail app flow."
                    "sms", "smsto", "mms", "mmsto" -> "This would open a messaging app conversation or compose flow."
                    else -> "This would open a link or deep link in another app."
                }
                Intent.ACTION_DIAL -> out += "This would open the dialer with a phone number."
                Intent.ACTION_CALL -> out += "This would place a phone call."
                Intent.ACTION_SEND -> out += "This would share data with another app."
                Intent.ACTION_SENDTO -> out += "This would hand off to an app for the target URI, such as mail or messaging."
                Intent.ACTION_EDIT -> out += "This would open another app to edit existing data."
                Intent.ACTION_PICK -> out += "This would let the user pick data from another app."
                Intent.ACTION_CHOOSER -> out += "This would show the system chooser so the user can pick a target app."
                Intent.ACTION_GET_CONTENT -> out += "This would let the user select a file or other content from another app."
                Intent.ACTION_OPEN_DOCUMENT -> out += "This would open the system document picker."
                Intent.ACTION_CREATE_DOCUMENT -> out += "This would ask the user where to create a new document."
                Intent.ACTION_MAIN -> out += "This would launch or foreground another app component."
                Intent.ACTION_DELETE -> out += "This would request deletion of the target item."
                Intent.ACTION_INSERT -> out += "This would request creation of a new item in another app."
            }
            intent.data?.let { uri ->
                if (uri.scheme == "content") {
                    out += uriWarnings(null, uri)
                }
            }
            return out.toList()
        }

        private fun uriWarnings(call: BinderCallInfo?, uri: Uri?): List<String> {
            uri ?: return emptyList()
            val out = linkedSetOf<String>()
            val verb = when (call?.methodName) {
                "query", "getType", "getStreamTypes" -> "read"
                "insert" -> "insert into"
                "update" -> "modify"
                "delete" -> "delete from"
                else -> "access"
            }
            when (uri.authority) {
                "com.android.calendar" ->
                    out += "This would $verb calendar events from the Android Calendar."
                "com.android.contacts", "contacts" ->
                    out += "This would $verb contacts data."
                "call_log" ->
                    out += "This would $verb the device call history."
                "sms", "mms", "mms-sms" ->
                    out += "This would $verb text or multimedia messages."
                "media", "com.android.providers.media.documents" ->
                    out += "This would $verb photos, videos, audio, or other media files."
                "downloads", "com.android.providers.downloads.documents" ->
                    out += "This would $verb downloaded files."
                "settings" ->
                    out += "This would $verb system or app settings data."
                "com.android.externalstorage.documents" ->
                    out += "This would $verb files from shared or external storage."
                "browser", "com.android.browser", "com.sec.android.app.sbrowser" ->
                    out += "This would $verb browser history, bookmarks, or tabs."
                "com.google.android.gm", "gmail-ls" ->
                    out += "This would $verb Gmail app data."
                "com.whatsapp.provider.media" ->
                    out += "This would $verb WhatsApp media."
            }
            return out.toList()
        }
    }

    private object DiffCallback : DiffUtil.ItemCallback<PendingRequest>() {
        override fun areItemsTheSame(oldItem: PendingRequest, newItem: PendingRequest): Boolean {
            return oldItem.sessionId == newItem.sessionId &&
                oldItem.notificationId == newItem.notificationId
        }

        override fun areContentsTheSame(oldItem: PendingRequest, newItem: PendingRequest): Boolean {
            return oldItem == newItem
        }
    }
}
