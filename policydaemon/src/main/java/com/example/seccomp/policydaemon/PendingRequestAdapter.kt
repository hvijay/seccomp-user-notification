package com.example.seccomp.policydaemon

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
            val body = buildString {
                appendLine(item.description)
                appendLine("notificationId=${item.notificationId}")
                appendLine("session=${item.sessionId}")
                appendLine("ioctlCmd=0x${item.ioctlCmd.toString(16)}")
                appendLine("monitor=${item.monitorStatus}")
                if (item.cgroupPath.isNotEmpty()) {
                    appendLine("cgroup=${item.cgroupPath}")
                }
                if (item.binderInterface.isNotEmpty()) {
                    appendLine("interface=${item.binderInterface}")
                }
                if (item.targetHandle != 0) {
                    appendLine("targetHandle=${item.targetHandle}")
                }
                if (item.intentAction.isNotEmpty()) {
                    appendLine("intentAction=${item.intentAction}")
                }
                if (item.intentUri.isNotEmpty()) {
                    appendLine("intentUri=${item.intentUri}")
                }
                if (item.parcelTruncated) {
                    append("parcelTruncated=true")
                }
            }.trim()
            binding.titleText.text = header
            binding.bodyText.text = body
            binding.allowButton.setOnClickListener { onAllow(item) }
            binding.denyButton.setOnClickListener { onDeny(item) }
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
