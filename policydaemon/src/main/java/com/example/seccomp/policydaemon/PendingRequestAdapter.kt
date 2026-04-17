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
            binding.titleText.text = "pid=${item.pid}, syscall=${item.syscallNr}"
            binding.bodyText.text =
                "${item.description}\nnotificationId=${item.notificationId}\nsession=${item.sessionId}"
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
