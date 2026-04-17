package com.example.seccomp.policydaemon

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.content.ContextCompat.startForegroundService
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.LinearLayoutManager
import com.example.seccomp.policydaemon.databinding.ActivityMainBinding
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private lateinit var adapter: PendingRequestAdapter

    private val notificationPermissionRequester =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        startForegroundService(this, Intent(this, PolicyDaemonService::class.java))
        requestNotificationPermissionIfNeeded()

        adapter = PendingRequestAdapter(
            onAllow = { SeccompRepository.allow(it) },
            onDeny = { SeccompRepository.deny(it) },
        )
        binding.requestsList.layoutManager = LinearLayoutManager(this)
        binding.requestsList.adapter = adapter

        lifecycleScope.launch {
            repeatOnLifecycle(androidx.lifecycle.Lifecycle.State.STARTED) {
                SeccompRepository.state.collect { state ->
                    binding.summaryText.text =
                        "Active sessions: ${state.activeSessionCount}, pending: ${state.pendingRequests.size}"
                    binding.detailText.text = state.lastStatus
                    adapter.submitList(state.pendingRequests)
                }
            }
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            return
        }
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        notificationPermissionRequester.launch(Manifest.permission.POST_NOTIFICATIONS)
    }
}
