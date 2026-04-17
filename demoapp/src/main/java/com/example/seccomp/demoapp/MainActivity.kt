package com.example.seccomp.demoapp

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.seccomp.demoapp.databinding.ActivityMainBinding
import com.example.seccomp.shared.ISeccompPolicyDaemon
import com.example.seccomp.shared.ServiceContract
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private var daemon: ISeccompPolicyDaemon? = null
    private var bound = false
    private var lastResultMessage: String? = null
    private var demoInFlight = false

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            daemon = ISeccompPolicyDaemon.Stub.asInterface(service)
            bound = true
            if (!demoInFlight && lastResultMessage == null) {
                updateStatus("Policy daemon connected.")
            }
            binding.startDemoButton.isEnabled = !demoInFlight
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            daemon = null
            bound = false
            if (!demoInFlight && lastResultMessage == null) {
                updateStatus("Policy daemon disconnected.")
            }
            binding.startDemoButton.isEnabled = false
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.openDaemonButton.setOnClickListener {
            val intent = Intent().setClassName(
                ServiceContract.DAEMON_PACKAGE,
                ServiceContract.DAEMON_ACTIVITY,
            )
            runCatching { startActivity(intent) }
                .onFailure { showToast("Policy daemon app is not installed.") }
        }

        binding.bindDaemonButton.setOnClickListener {
            bindToDaemon()
        }

        binding.startDemoButton.setOnClickListener {
            runDemo()
        }
    }

    override fun onStart() {
        super.onStart()
        bindToDaemon()
    }

    override fun onStop() {
        super.onStop()
        if (bound) {
            unbindService(connection)
            bound = false
        }
        daemon = null
        binding.startDemoButton.isEnabled = false
    }

    private fun bindToDaemon() {
        if (bound) {
            return
        }
        val intent = Intent(ServiceContract.DAEMON_BIND_ACTION).apply {
            setClassName(ServiceContract.DAEMON_PACKAGE, ServiceContract.DAEMON_SERVICE)
        }
        val ok = bindService(intent, connection, Context.BIND_AUTO_CREATE)
        if (!ok) {
            updateStatus("Binding failed. Install and launch the policy daemon app.")
        }
    }

    private fun runDemo() {
        val currentDaemon = daemon ?: run {
            updateStatus("Policy daemon not connected.")
            return
        }

        demoInFlight = true
        lastResultMessage = null
        binding.startDemoButton.isEnabled = false
        updateStatus("Installing filter on helper thread and forking child...")

        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                NativeSeccompBridge.installFilterForkAndTrigger("/proc/version")
            }

            if (result.size < 2) {
                demoInFlight = false
                binding.startDemoButton.isEnabled = true
                updateStatus("Native bridge returned an invalid result.")
                return@launch
            }

            val listenerFd = result[0]
            val childPid = result[1]
            val resultFd = result.getOrNull(2) ?: -1
            if (listenerFd < 0) {
                demoInFlight = false
                binding.startDemoButton.isEnabled = true
                updateStatus("Failed to install seccomp filter. errno=${-listenerFd}, aux=$childPid")
                return@launch
            }

            val sessionId = "session-${System.currentTimeMillis()}"
            val description = "Intercept openat(\"/proc/version\") from forked child pid=$childPid"

            val registered = runCatching {
                ParcelFileDescriptor.adoptFd(listenerFd).use { pfd ->
                    currentDaemon.registerSession(sessionId, pfd, description)
                }
            }.getOrElse { error ->
                updateStatus("Failed to send listener FD to daemon: ${error.message}")
                false
            }

            updateStatus(
                if (registered) {
                    "Listener handed to daemon. Review request in policy daemon app for child pid=$childPid."
                } else {
                    "Daemon rejected the listener registration."
                },
            )

            if (registered && resultFd >= 0) {
                lifecycleScope.launch {
                    val outcome = withContext(Dispatchers.IO) {
                        NativeSeccompBridge.readChildResult(resultFd)
                    }
                    demoInFlight = false
                    lastResultMessage = outcome
                    updateStatus(outcome)
                    binding.startDemoButton.isEnabled = bound
                }
            } else {
                demoInFlight = false
            }
            if (!registered) {
                binding.startDemoButton.isEnabled = true
            }
        }
    }

    private fun updateStatus(message: String) {
        binding.statusText.text = message
    }

    private fun showToast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }
}
