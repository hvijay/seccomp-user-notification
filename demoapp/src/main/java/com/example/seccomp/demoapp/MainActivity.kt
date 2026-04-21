package com.example.seccomp.demoapp

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.Uri
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
    private var pendingIntentRun = false

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            daemon = ISeccompPolicyDaemon.Stub.asInterface(service)
            bound = true
            if (!demoInFlight && lastResultMessage == null) {
                updateStatus("Policy daemon connected.")
            }
            binding.startDemoButton.isEnabled = !demoInFlight
            maybeRunPendingIntentDemo()
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

        handleLaunchIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleLaunchIntent(intent)
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

    private fun handleLaunchIntent(intent: Intent?) {
        if (intent?.action != ServiceContract.DEMO_RUN_ACTION) {
            return
        }
        pendingIntentRun = true
        if (bound) {
            maybeRunPendingIntentDemo()
        } else {
            updateStatus("RUN_DEMO intent received. Waiting for policy daemon bind.")
            bindToDaemon()
        }
    }

    private fun maybeRunPendingIntentDemo() {
        if (!pendingIntentRun || demoInFlight || !bound) {
            return
        }
        pendingIntentRun = false
        runDemo()
    }

    private fun runDemo() {
        val currentDaemon = daemon ?: run {
            updateStatus("Policy daemon not connected.")
            return
        }

        demoInFlight = true
        lastResultMessage = null
        binding.startDemoButton.isEnabled = false
        updateStatus("Installing Binder ioctl filter, forking child, and issuing a native VIEW intent...")

        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                NativeSeccompBridge.installFilterForkAndTriggerIntent(
                    ServiceContract.DEMO_NATIVE_ACTION,
                    "",
                    "",
                    ServiceContract.DEMO_NATIVE_URI,
                )
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
            val goWriteFd = result.getOrNull(3) ?: -1
            if (listenerFd < 0) {
                demoInFlight = false
                binding.startDemoButton.isEnabled = true
                updateStatus("Failed to install seccomp filter. errno=${-listenerFd}, aux=$childPid")
                return@launch
            }

            val sessionId = "session-${System.currentTimeMillis()}"
            val myPid = android.os.Process.myPid()
            val description =
                "Intercept ioctl(BINDER_WRITE_READ) from forked child pid=$childPid while it opens ${ServiceContract.DEMO_NATIVE_URI}."

            val localListenerFd = ParcelFileDescriptor.adoptFd(listenerFd).detachFd()
            val registered = runCatching {
                ParcelFileDescriptor.fromFd(localListenerFd).use { pfd ->
                    currentDaemon.registerSession(sessionId, pfd, description, myPid)
                }
            }.getOrElse { error ->
                updateStatus("Failed to send listener FD to daemon: ${error.message}")
                false
            }

            updateStatus(
                if (registered) {
                    "Listener transferred to loader daemon. Review Binder ioctl request in policy daemon app for child pid=$childPid (cgroup from myPid=$myPid)."
                } else {
                    "Daemon rejected the listener registration."
                },
            )

            /* registerSession is synchronous: by the time it returns, nativeStartListener
               has already sent SET_TARGET to the loader and the BPF cgroup filter is armed.
               Signal the child now so its ioctl(BINDER_WRITE_READ) is captured by eBPF. */
            if (goWriteFd >= 0) {
                NativeSeccompBridge.triggerChild(goWriteFd)
            }

            if (registered && resultFd >= 0) {
                NativeSeccompBridge.closeFd(localListenerFd)
                lifecycleScope.launch {
                    val outcome = withContext(Dispatchers.IO) {
                        NativeSeccompBridge.readChildResult(resultFd)
                    }
                    runCatching { currentDaemon.unregisterSession(sessionId) }
                    demoInFlight = false
                    lastResultMessage = outcome
                    if (outcome.contains("seccomp allowed")) {
                        launchVisibleDemoIntent()
                    }
                    updateStatus(outcome)
                    binding.startDemoButton.isEnabled = bound
                }
            } else {
                demoInFlight = false
                NativeSeccompBridge.closeFd(localListenerFd)
            }
            if (!registered) {
                /* Unblock and discard the child — nobody is listening. */
                if (goWriteFd >= 0) NativeSeccompBridge.triggerChild(goWriteFd)
                binding.startDemoButton.isEnabled = true
            }
        }
    }

    private fun updateStatus(message: String) {
        DebugStateStore.updateStatus(message)
        binding.statusText.text = message
    }

    private fun launchVisibleDemoIntent() {
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(ServiceContract.DEMO_NATIVE_URI)).apply {
            addCategory(Intent.CATEGORY_BROWSABLE)
        }
        runCatching { startActivity(intent) }
            .onFailure { error ->
                showToast("Allowed, but browser launch failed: ${error.message}")
            }
    }

    private fun showToast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }
}
