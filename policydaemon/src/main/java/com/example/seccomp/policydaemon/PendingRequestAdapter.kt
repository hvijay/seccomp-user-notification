package com.example.seccomp.policydaemon

import android.graphics.Color
import android.graphics.Typeface
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
                append("tid=${item.pid}, targetPid=${item.targetPid}, syscall=${item.syscallNr}")
                if (item.binderCode != 0 || item.binderInterface.isNotEmpty()) {
                    append(", code=${item.binderCode}")
                }
            }
            val body = SpannableStringBuilder().apply {
                appendLine(item.description)
                if (item.intentAction.isNotEmpty() || item.intentUri.isNotEmpty()) {
                    appendHighlightedLine(
                        "Intent",
                        buildString {
                            if (item.intentAction.isNotEmpty()) {
                                append(item.intentAction)
                            }
                            if (item.intentUri.isNotEmpty()) {
                                if (isNotEmpty()) append(" -> ")
                                append(item.intentUri)
                            }
                        },
                    )
                    if (item.intentAction == "android.intent.action.VIEW") {
                        appendHighlightedLine("Meaning", "This would open a link in a browser/app")
                    }
                }
                appendNormalLine("notificationId", item.notificationId.toString())
                appendNormalLine("session", item.sessionId)
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
