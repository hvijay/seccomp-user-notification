package com.example.seccomp.demoapp

import android.Manifest
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.provider.CalendarContract
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.example.seccomp.demoapp.databinding.ActivityMainBinding
import com.example.seccomp.shared.ISeccompPolicyDaemon
import com.example.seccomp.shared.ServiceContract
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.util.Date

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private var daemon: ISeccompPolicyDaemon? = null
    private var bound = false
    private var lastResultMessage: String? = null
    private var demoInFlight = false
    private var pendingIntentRun = false

    private val calendarPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) {
            loadAndDisplayCalendarEvents()
        } else {
            binding.eventsText.text = "READ_CALENDAR permission denied — cannot display events."
        }
    }

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
        requestCalendarPermissionOrLoad()
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

    private fun requestCalendarPermissionOrLoad() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_CALENDAR)
            == PackageManager.PERMISSION_GRANTED
        ) {
            loadAndDisplayCalendarEvents()
        } else {
            calendarPermissionLauncher.launch(Manifest.permission.READ_CALENDAR)
        }
    }

    private fun loadAndDisplayCalendarEvents() {
        lifecycleScope.launch {
            val events = withContext(Dispatchers.IO) { queryCalendarEvents() }
            binding.eventsText.text = if (events.isEmpty()) {
                "No upcoming events found."
            } else {
                events.joinToString("\n")
            }
        }
    }

    private fun queryCalendarEvents(): List<String> {
        val projection = arrayOf(
            CalendarContract.Events.TITLE,
            CalendarContract.Events.DTSTART,
        )
        val now = System.currentTimeMillis()
        val cursor = contentResolver.query(
            CalendarContract.Events.CONTENT_URI,
            projection,
            "${CalendarContract.Events.DTSTART} >= ?",
            arrayOf(now.toString()),
            "${CalendarContract.Events.DTSTART} ASC",
        ) ?: return emptyList()
        return cursor.use { c ->
            val fmt = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
            buildList {
                val titleIdx = c.getColumnIndexOrThrow(CalendarContract.Events.TITLE)
                val startIdx = c.getColumnIndexOrThrow(CalendarContract.Events.DTSTART)
                while (c.moveToNext() && size < 10) {
                    val title = c.getString(titleIdx) ?: "(no title)"
                    val start = fmt.format(Date(c.getLong(startIdx)))
                    add("• $title  ($start)")
                }
            }
        }
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
        updateStatus("Installing Binder ioctl filter, forking child, and issuing a raw IContentProvider.query() for the calendar…")

        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                NativeSeccompBridge.installFilterForkAndTriggerIntent(
                    "query",
                    "",
                    "",
                    "content://com.android.calendar/events",
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
            val description =
                "Intercept ioctl(BINDER_WRITE_READ) from forked child pid=$childPid " +
                "querying content://com.android.calendar/events."

            val localListenerFd = ParcelFileDescriptor.adoptFd(listenerFd).detachFd()
            val registered = runCatching {
                ParcelFileDescriptor.fromFd(localListenerFd).use { pfd ->
                    currentDaemon.registerSession(sessionId, pfd, description, childPid)
                }
            }.getOrElse { error ->
                updateStatus("Failed to send listener FD to daemon: ${error.message}")
                false
            }

            updateStatus(
                if (registered) {
                    "Listener transferred to loader daemon. Review calendar query request in policy daemon app for child pid=$childPid."
                } else {
                    "Daemon rejected the listener registration."
                },
            )

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
                    updateStatus(outcome)
                    binding.startDemoButton.isEnabled = bound
                }
            } else {
                demoInFlight = false
                NativeSeccompBridge.closeFd(localListenerFd)
            }
            if (!registered) {
                if (goWriteFd >= 0) NativeSeccompBridge.triggerChild(goWriteFd)
                binding.startDemoButton.isEnabled = true
            }
        }
    }

    private fun updateStatus(message: String) {
        DebugStateStore.updateStatus(message)
        binding.statusText.text = message
    }

    private fun showToast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }
}
