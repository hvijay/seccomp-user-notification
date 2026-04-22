package com.example.seccomp.demoapp

import android.Manifest
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.os.Parcel
import android.os.ParcelFileDescriptor
import android.provider.CalendarContract
import android.util.Log
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
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
import java.io.File
import java.text.DateFormat
import java.util.Date

class MainActivity : AppCompatActivity() {
    companion object {
        private const val EXTRA_AGENT_ACTION = "agent_action"
        private const val TAG = "SeccompDemoApp"
    }

    private lateinit var binding: ActivityMainBinding
    private var daemon: ISeccompPolicyDaemon? = null
    private var bound = false
    private var lastResultMessage: String? = null
    private var demoInFlight = false
    private var pendingAutoAction: AgentAction? = null

    private val calendarPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (!granted) {
            showResponse("Calendar", "READ_CALENDAR permission denied.")
            addAssistantMessage("I can still request the calendar Binder call, but I cannot print the real event list without permission.")
        }
    }

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            daemon = ISeccompPolicyDaemon.Stub.asInterface(service)
            bound = true
            binding.connectionStatusText.text = "Policy daemon connected"
            binding.connectionStatusText.setTextColor(0xFF63F29A.toInt())
            updateActionButtons()
            maybeRunPendingAutoAction()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            daemon = null
            bound = false
            binding.connectionStatusText.text = "Waiting for policy daemon"
            binding.connectionStatusText.setTextColor(0xFFFFB84D.toInt())
            updateActionButtons()
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
        binding.bindDaemonButton.setOnClickListener { bindToDaemon() }

        binding.calendarActionButton.setOnClickListener { runAgentAction(AgentAction.PRINT_CALENDAR) }
        binding.browserActionButton.setOnClickListener { runAgentAction(AgentAction.OPEN_BROWSER) }
        binding.emailActionButton.setOnClickListener { runAgentAction(AgentAction.SEND_EMAIL) }
        binding.readContextActionButton.setOnClickListener { runAgentAction(AgentAction.READ_CONTEXT_FILE) }
        binding.execCurlActionButton.setOnClickListener { runAgentAction(AgentAction.EXECUTE_WEB_SEARCH) }

        seedConversation()
        ensureWorkspaceContextFile()
        handleLaunchIntent(intent)
        updateActionButtons()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleLaunchIntent(intent)
    }

    override fun onStart() {
        super.onStart()
        bindToDaemon()
        ensureCalendarPermission()
    }

    override fun onStop() {
        super.onStop()
        if (bound) {
            unbindService(connection)
            bound = false
        }
        daemon = null
        updateActionButtons()
    }

    private fun seedConversation() {
        addAssistantMessage("Atlas is ready. Pick a hardcoded action below and I’ll request approval before it runs.")
        addAssistantMessage("Try: print your calendar, open a browser tab, read CONTEXT.md, or run a curl web search.")
    }

    private fun ensureCalendarPermission() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_CALENDAR)
            != PackageManager.PERMISSION_GRANTED
        ) {
            calendarPermissionLauncher.launch(Manifest.permission.READ_CALENDAR)
        }
    }

    private fun bindToDaemon() {
        if (bound) return
        val intent = Intent(ServiceContract.DAEMON_BIND_ACTION).apply {
            setClassName(ServiceContract.DAEMON_PACKAGE, ServiceContract.DAEMON_SERVICE)
        }
        val ok = bindService(intent, connection, Context.BIND_AUTO_CREATE)
        if (!ok) {
            binding.connectionStatusText.text = "Bind failed"
            binding.connectionStatusText.setTextColor(0xFFFF7272.toInt())
            addAssistantMessage("I couldn’t bind to the policy daemon. Open it first, then reconnect.")
        }
    }

    private fun handleLaunchIntent(intent: Intent?) {
        if (intent?.action != ServiceContract.DEMO_RUN_ACTION) return
        pendingAutoAction = AgentAction.fromExtra(intent.getStringExtra(EXTRA_AGENT_ACTION))
        if (bound) {
            maybeRunPendingAutoAction()
        } else {
            addAssistantMessage("Auto-run requested. Waiting for the policy daemon connection first.")
            bindToDaemon()
        }
    }

    private fun maybeRunPendingAutoAction() {
        val action = pendingAutoAction ?: return
        if (!bound || demoInFlight) return
        pendingAutoAction = null
        runAgentAction(action)
    }

    private fun runAgentAction(action: AgentAction) {
        addUserMessage(action.prompt)
        clearResponse()

        val currentDaemon = daemon ?: run {
            addAssistantMessage("The policy daemon is not connected yet.")
            return
        }

        demoInFlight = true
        lastResultMessage = null
        updateActionButtons()
        DebugStateStore.updateStatus("Requesting ${action.prompt}")
        addAssistantMessage("Preparing “${action.prompt}” and handing approval to the policy daemon.")

        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                when (action) {
                    AgentAction.PRINT_CALENDAR,
                    AgentAction.OPEN_BROWSER,
                    AgentAction.SEND_EMAIL,
                    -> {
                        val rawParcel = buildParcelForAction(action)
                        NativeSeccompBridge.installFilterForkAndTriggerTransaction(
                            action.transactionCode,
                            rawParcel,
                            action.outcomeLabel,
                        )
                    }

                    AgentAction.READ_CONTEXT_FILE -> {
                        NativeSeccompBridge.installFilterForkAndReadFile(
                            workspaceContextFile().absolutePath,
                            android.system.OsConstants.O_RDONLY,
                            action.outcomeLabel,
                        )
                    }

                    AgentAction.EXECUTE_WEB_SEARCH -> {
                        val command = resolveCurlCommand()
                        NativeSeccompBridge.installFilterForkAndExec(
                            command.first,
                            command.second.toTypedArray(),
                            action.outcomeLabel,
                        )
                    }
                }
            }

            if (result.size < 2) {
                finishFailedRun("Native bridge returned an invalid result.")
                return@launch
            }

            val listenerFd = result[0]
            val childPid = result[1]
            val resultFd = result.getOrNull(2) ?: -1
            val goWriteFd = result.getOrNull(3) ?: -1
            if (listenerFd < 0) {
                finishFailedRun("Failed to install seccomp filter. errno=${-listenerFd}, aux=$childPid")
                return@launch
            }

            val sessionId = "session-${System.currentTimeMillis()}"
            val description = action.policyDescription(childPid)
            val localListenerFd = ParcelFileDescriptor.adoptFd(listenerFd).detachFd()
            val registered = runCatching {
                ParcelFileDescriptor.fromFd(localListenerFd).use { pfd ->
                    currentDaemon.registerSession(sessionId, pfd, description, childPid)
                }
            }.getOrElse { error ->
                addAssistantMessage("Failed to send the listener FD to the policy daemon: ${error.message}")
                false
            }

            if (registered) {
                addAssistantMessage("Approval requested. Review the action in the policy daemon for child pid=$childPid.")
            } else {
                addAssistantMessage("The policy daemon rejected the listener registration.")
            }

            if (goWriteFd >= 0) {
                NativeSeccompBridge.triggerChild(goWriteFd)
            }

            if (registered && resultFd >= 0) {
                NativeSeccompBridge.closeFd(localListenerFd)
                val outcome = withContext(Dispatchers.IO) {
                    NativeSeccompBridge.readChildResult(resultFd)
                }
                runCatching { currentDaemon.unregisterSession(sessionId) }
                handleCompletedAction(action, outcome)
            } else {
                demoInFlight = false
                NativeSeccompBridge.closeFd(localListenerFd)
                updateActionButtons()
                if (!registered) {
                    if (goWriteFd >= 0) NativeSeccompBridge.triggerChild(goWriteFd)
                }
            }
        }
    }

    private suspend fun handleCompletedAction(action: AgentAction, outcome: String) {
        demoInFlight = false
        lastResultMessage = outcome
        DebugStateStore.updateStatus(outcome)
        updateActionButtons()

        if (outcome.contains("denied", ignoreCase = true)) {
            addAssistantMessage("The policy daemon denied “${action.prompt}”.")
            return
        }

        when (action) {
            AgentAction.PRINT_CALENDAR -> {
                val events = withContext(Dispatchers.IO) { queryCalendarEvents() }
                val body = if (events.isEmpty()) {
                    "No upcoming events found."
                } else {
                    events.joinToString("\n")
                }
                showResponse("Calendar", body)
                addAssistantMessage("Here are your upcoming calendar events.")
            }

            AgentAction.OPEN_BROWSER -> {
                runCatching {
                    startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(ServiceContract.DEMO_NATIVE_URI)))
                }.onFailure {
                    addAssistantMessage("The browser request was approved, but Android could not open a browser.")
                    return
                }
                addAssistantMessage("Opening the browser now.")
            }

            AgentAction.SEND_EMAIL -> {
                val mailIntent = Intent(Intent.ACTION_SENDTO, Uri.parse("mailto:security-demo@example.com"))
                    .putExtra(Intent.EXTRA_SUBJECT, "Hello from Atlas")
                    .putExtra(Intent.EXTRA_TEXT, "This draft was launched after seccomp approval.")
                runCatching { startActivity(mailIntent) }
                    .onFailure {
                        addAssistantMessage("The email request was approved, but no mail app handled it.")
                        return
                    }
                addAssistantMessage("Opening an email draft now.")
            }

            AgentAction.READ_CONTEXT_FILE -> {
                showResponse("CONTEXT.md", outcome.removePrefix("Child result: ").trim())
                addAssistantMessage("Here is the current workspace CONTEXT.md.")
            }

            AgentAction.EXECUTE_WEB_SEARCH -> {
                showResponse("curl https://example.com/", outcome.removePrefix("Child result: ").trim())
                addAssistantMessage("The web search tool finished and returned its output.")
            }
        }
    }

    private fun finishFailedRun(message: String) {
        demoInFlight = false
        updateActionButtons()
        DebugStateStore.updateStatus(message)
        addAssistantMessage(message)
    }

    private fun buildParcelForAction(action: AgentAction): ByteArray = when (action) {
        AgentAction.PRINT_CALENDAR -> {
            buildContentProviderQueryParcel(CalendarContract.Events.CONTENT_URI)
        }

        AgentAction.OPEN_BROWSER -> {
            buildStartActivityParcel(
                Intent(Intent.ACTION_VIEW, Uri.parse(ServiceContract.DEMO_NATIVE_URI)),
            )
        }

        AgentAction.SEND_EMAIL -> {
            buildStartActivityParcel(
                Intent(Intent.ACTION_SENDTO, Uri.parse("mailto:security-demo@example.com")),
            )
        }

        AgentAction.READ_CONTEXT_FILE,
        AgentAction.EXECUTE_WEB_SEARCH,
        -> ByteArray(0)
    }

    private fun buildContentProviderQueryParcel(uri: Uri): ByteArray {
        val parcel = Parcel.obtain()
        return try {
            writeCommonHeader(parcel, "android.content.IContentProvider")
            parcel.writeString(packageName)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                parcel.writeString(null)
            }
            parcel.writeInt(1) // typed-object present
            parcel.writeInt(1) // StringUri
            parcel.writeString(uri.toString())
            parcel.marshall()
        } finally {
            parcel.recycle()
        }
    }

    private fun buildStartActivityParcel(intent: Intent): ByteArray {
        val parcel = Parcel.obtain()
        return try {
            writeCommonHeader(parcel, "android.app.IActivityTaskManager")
            parcel.writeLong(0L)
            parcel.writeLong(0L)
            parcel.writeLong(0L)
            parcel.writeString(packageName)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                parcel.writeString(null)
            }
            parcel.writeInt(1) // typed-object present
            intent.writeToParcel(parcel, 0)
            parcel.marshall().also {
                logStartActivityParcelPreview(it)
            }
        } finally {
            parcel.recycle()
        }
    }

    private fun writeCommonHeader(parcel: Parcel, interfaceDescriptor: String) {
        parcel.writeInt(0)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            parcel.writeInt(-1)
        }
        parcel.writeString(interfaceDescriptor)
    }

    private fun logStartActivityParcelPreview(rawParcel: ByteArray) {
        val parcel = Parcel.obtain()
        try {
            parcel.unmarshall(rawParcel, 0, rawParcel.size)
            parcel.setDataPosition(0)
            parcel.readInt()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                parcel.readInt()
            }
            val descriptor = parcel.readString()
            parcel.setDataPosition(parcel.dataPosition() + 24)
            val pkg = parcel.readString()
            val feature = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                parcel.readString()
            } else {
                null
            }
            val present = parcel.readInt()
            val parsedIntent = if (present == 1) Intent.CREATOR.createFromParcel(parcel) else null
            Log.d(
                TAG,
                "preview descriptor=$descriptor pkg=$pkg feature=$feature present=$present " +
                    "action=${parsedIntent?.action} data=${parsedIntent?.data}",
            )
        } catch (t: Throwable) {
            Log.w(TAG, "startActivity parcel preview failed", t)
        } finally {
            parcel.recycle()
        }
    }

    private fun queryCalendarEvents(): List<String> {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_CALENDAR)
            != PackageManager.PERMISSION_GRANTED
        ) {
            return listOf("READ_CALENDAR permission denied.")
        }
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

    private fun updateActionButtons() {
        val enabled = bound && !demoInFlight
        binding.calendarActionButton.isEnabled = enabled
        binding.browserActionButton.isEnabled = enabled
        binding.emailActionButton.isEnabled = enabled
        binding.readContextActionButton.isEnabled = enabled
        binding.execCurlActionButton.isEnabled = enabled
    }

    private fun workspaceContextFile(): File =
        File(File(filesDir, "workspace"), "CONTEXT.md")

    private fun ensureWorkspaceContextFile() {
        val file = workspaceContextFile()
        if (file.exists()) return
        file.parentFile?.mkdirs()
        file.writeText(
            """
            # Demo Workspace Context

            This file is created by the seccomp demo app.
            It exists so the "Read workspace file CONTEXT.md" action can trigger a real openat() decision.
            """.trimIndent() + "\n",
        )
    }

    private fun resolveCurlCommand(): Pair<String, List<String>> {
        val directCurl = File("/system/bin/curl")
        if (directCurl.exists()) {
            return directCurl.absolutePath to listOf("curl", "https://example.com/")
        }
        val toybox = File("/system/bin/toybox")
        return toybox.absolutePath to listOf("toybox", "curl", "https://example.com/")
    }

    private fun addUserMessage(message: String) {
        addChatBubble(message, fromUser = true)
    }

    private fun addAssistantMessage(message: String) {
        addChatBubble(message, fromUser = false)
    }

    private fun addChatBubble(message: String, fromUser: Boolean) {
        val row = LinearLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply {
                topMargin = dp(10)
            }
            gravity = if (fromUser) Gravity.END else Gravity.START
        }

        val bubble = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                0,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply {
                width = dp(280)
            }
            text = message
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
            setTypeface(typeface, if (fromUser) Typeface.BOLD else Typeface.NORMAL)
            setTextColor(if (fromUser) 0xFF07111A.toInt() else 0xFFE8F1FF.toInt())
            setPadding(dp(16), dp(14), dp(16), dp(14))
            background = GradientDrawable().apply {
                cornerRadius = dp(22).toFloat()
                setColor(if (fromUser) 0xFF9FE870.toInt() else 0xFF162236.toInt())
            }
        }

        row.addView(bubble)
        binding.chatContainer.addView(row)
        binding.chatScroll.post { binding.chatScroll.fullScroll(View.FOCUS_DOWN) }
    }

    private fun showResponse(title: String, body: String) {
        binding.responseCard.visibility = View.VISIBLE
        binding.responseTitleText.text = title
        binding.responseText.text = body
    }

    private fun clearResponse() {
        binding.responseCard.visibility = View.GONE
        binding.responseText.text = ""
    }

    private fun dp(value: Int): Int =
        TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP,
            value.toFloat(),
            resources.displayMetrics,
        ).toInt()

    private fun showToast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    private enum class AgentAction(
        val prompt: String,
        val outcomeLabel: String,
    ) {
        PRINT_CALENDAR(
            prompt = "Print my calendar",
            outcomeLabel = "Calendar query",
        ),
        OPEN_BROWSER(
            prompt = "Open the browser",
            outcomeLabel = "Browser launch",
        ),
        SEND_EMAIL(
            prompt = "Send an email",
            outcomeLabel = "Email compose",
        ),
        READ_CONTEXT_FILE(
            prompt = "Read workspace file CONTEXT.md",
            outcomeLabel = "Workspace file read",
        ),
        EXECUTE_WEB_SEARCH(
            prompt = "Execute web search tool (curl)",
            outcomeLabel = "curl execution",
        ),
        ;

        val transactionCode: Int
            get() = 1

        fun policyDescription(childPid: Int): String = when (this) {
            PRINT_CALENDAR ->
                "Intercept ioctl(BINDER_WRITE_READ) from forked child pid=$childPid querying the Calendar content provider."
            OPEN_BROWSER ->
                "Intercept ioctl(BINDER_WRITE_READ) from forked child pid=$childPid starting an ACTION_VIEW browser intent."
            SEND_EMAIL ->
                "Intercept ioctl(BINDER_WRITE_READ) from forked child pid=$childPid starting an ACTION_SENDTO email intent."
            READ_CONTEXT_FILE ->
                "Intercept openat() from forked child pid=$childPid reading the app workspace CONTEXT.md file."
            EXECUTE_WEB_SEARCH ->
                "Intercept execve() from forked child pid=$childPid launching curl for https://example.com/."
        }

        companion object {
            fun fromExtra(value: String?): AgentAction = when (value?.lowercase()) {
                "calendar" -> PRINT_CALENDAR
                "email" -> SEND_EMAIL
                "context" -> READ_CONTEXT_FILE
                "curl" -> EXECUTE_WEB_SEARCH
                else -> OPEN_BROWSER
            }
        }
    }
}
