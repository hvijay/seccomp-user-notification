package com.example.seccomp.policydaemon

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Parcel
import android.util.Log

/**
 * Decodes raw Binder parcel bytes (captured by the loader via process_vm_readv)
 * into a [BinderCallInfo] with high-level semantics.
 *
 * Uses android.os.Parcel (libbinder's Java wrapper) for all deserialization so
 * that UTF-16 encoding, padding, and String16 framing are handled by the
 * platform's own code.
 *
 * Parcel header layout (all Binder transactions, Android 9+):
 *   [int32]  strict-mode policy
 *   [int32]  work-source UID
 *   [String] interface descriptor  ← readString16() via libbinder
 * Parameters follow in AIDL declaration order.
 */
object BinderParcelDecoder {

    private const val TAG = "BinderParcelDecoder"

    // sizeof(flat_binder_object) on arm64: type(4) + flags(4) + binder/handle(8) + cookie(8)
    private const val FLAT_BINDER_OBJECT_SIZE = 24

    fun decode(
        rawParcel: ByteArray,
        capturedBytes: Int,
        txnCode: Int,
        truncated: Boolean,
    ): BinderCallInfo {
        if (capturedBytes <= 0) {
            return BinderCallInfo(
                interfaceDescriptor = "",
                methodName = "code$txnCode",
                transactionCode = txnCode,
                args = emptyList(),
                parseError = if (truncated) null else "no parcel data captured",
                truncated = truncated,
            )
        }

        val p = Parcel.obtain()
        try {
            val valid = capturedBytes.coerceIn(0, rawParcel.size)
            p.unmarshall(rawParcel, 0, valid)
            p.setDataPosition(0)

            val descriptor = readHeader(p)
                ?: return BinderCallInfo(
                    interfaceDescriptor = "",
                    methodName = "code$txnCode",
                    transactionCode = txnCode,
                    args = emptyList(),
                    parseError = "could not read parcel header",
                    truncated = truncated,
                )

            val method = BinderInterfaceRegistry.methodName(descriptor, txnCode)
                ?: "code$txnCode"

            val (args, parseError) = safeParseArgs(p, descriptor, method)

            return BinderCallInfo(
                interfaceDescriptor = descriptor,
                methodName = method,
                transactionCode = txnCode,
                args = args,
                parseError = parseError,
                truncated = truncated,
            )
        } catch (e: Exception) {
            Log.w(TAG, "decode failed code=$txnCode: $e")
            return BinderCallInfo(
                interfaceDescriptor = "",
                methodName = "code$txnCode",
                transactionCode = txnCode,
                args = emptyList(),
                parseError = e.message?.take(80),
                truncated = truncated,
            )
        } finally {
            p.recycle()
        }
    }

    // ── Header ────────────────────────────────────────────────────────────────

    private fun readHeader(p: Parcel): String? = runCatching {
        p.readInt()  // strict-mode policy
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            p.readInt()  // work-source UID (API 28+)
        }
        p.readString()  // interface descriptor via libbinder readString16()
    }.getOrNull()

    // ── Dispatch ──────────────────────────────────────────────────────────────

    private fun safeParseArgs(
        p: Parcel,
        descriptor: String,
        method: String,
    ): Pair<List<BinderArg>, String?> {
        return try {
            val args = when (descriptor) {
                "android.app.IActivityManager" ->
                    parseActivityManager(p, method)
                "android.app.IActivityTaskManager" ->
                    parseActivityTaskManager(p, method)
                "android.content.IContentProvider" ->
                    parseContentProvider(p, method)
                else -> emptyList()
            }
            Pair(args, null)
        } catch (e: Exception) {
            Log.d(TAG, "partial parse $descriptor.$method: $e")
            Pair(emptyList(), "partial: ${e.message?.take(60)}")
        }
    }

    // ── IActivityManager ──────────────────────────────────────────────────────

    private fun parseActivityManager(p: Parcel, method: String): List<BinderArg> = when (method) {
        "startActivity", "startActivityAsUser",
        "startActivityAsCaller" -> startActivity(p)

        "broadcastIntent" -> broadcastIntent(p)
        "broadcastIntentWithFeature" -> broadcastIntentWithFeature(p)

        "startService", "startForegroundService",
        "startServiceAsUser" -> serviceIntent(p, "service")

        "bindService", "bindServiceInstance",
        "bindIsolatedService" -> serviceIntent(p, "service")

        "stopService" -> serviceIntent(p, "service")

        else -> tryStartActivityLike(p)
    }

    // ── IActivityTaskManager (API 29+) ────────────────────────────────────────

    private fun parseActivityTaskManager(p: Parcel, method: String): List<BinderArg> = when (method) {
        "startActivity", "startActivityAsUser",
        "startActivityWithConfig", "startActivityAsCaller" -> startActivity(p)

        else -> tryStartActivityLike(p)
    }

    // ── IContentProvider ──────────────────────────────────────────────────────

    private fun parseContentProvider(p: Parcel, method: String): List<BinderArg> = when (method) {
        "query" -> contentUriCall(p)
        "insert" -> contentUriCall(p)
        "update" -> contentUriCall(p)
        "delete" -> contentUriCall(p)
        "getType", "getStreamTypes" -> contentUriCall(p)
        else -> emptyList()
    }

    // ── Per-method schemas ────────────────────────────────────────────────────

    private fun startActivity(p: Parcel): List<BinderArg> = buildList {
        if (!skipBinder(p)) return@buildList
        readString(p, "callingPackage")?.let(::add) ?: return@buildList
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            readString(p, "callingFeatureId")?.let(::add) ?: return@buildList
        }
        val intentArg = readIntent(p, "intent") ?: return@buildList
        val intentValue = (intentArg as? BinderArg.IntentValue)?.intent ?: return@buildList
        if (!isMeaningfulIntent(intentValue)) return@buildList
        add(intentArg)
    }

    private fun tryStartActivityLike(p: Parcel): List<BinderArg> {
        val start = p.dataPosition()
        val parsed = runCatching { startActivity(p) }.getOrElse { emptyList() }
        if (parsed.isNotEmpty()) {
            return parsed
        }
        p.setDataPosition(start)
        return emptyList()
    }

    private fun broadcastIntent(p: Parcel): List<BinderArg> = buildList {
        if (!skipBinder(p)) return@buildList
        readIntent(p, "intent")?.let(::add) ?: return@buildList
    }

    private fun broadcastIntentWithFeature(p: Parcel): List<BinderArg> = buildList {
        if (!skipBinder(p)) return@buildList
        readString(p, "callingFeatureId")?.let(::add) ?: return@buildList
        readIntent(p, "intent")?.let(::add) ?: return@buildList
    }

    private fun serviceIntent(p: Parcel, intentName: String): List<BinderArg> = buildList {
        if (!skipBinder(p)) return@buildList
        readIntent(p, intentName)?.let(::add) ?: return@buildList
    }

    private fun contentUriCall(p: Parcel): List<BinderArg> = buildList {
        readString(p, "callingPkg")?.let(::add) ?: return@buildList
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            readString(p, "callingFeatureId")?.let(::add) ?: return@buildList
        }
        readUri(p, "uri")?.let(::add) ?: return@buildList
    }

    // ── Safe primitive readers ────────────────────────────────────────────────

    private fun skipBinder(p: Parcel): Boolean {
        val pos = p.dataPosition()
        if (pos + FLAT_BINDER_OBJECT_SIZE > p.dataSize()) return false
        p.setDataPosition(pos + FLAT_BINDER_OBJECT_SIZE)
        return true
    }

    private fun readString(p: Parcel, name: String): BinderArg? =
        runCatching { BinderArg.StringValue(name, p.readString()) }.getOrNull()

    private fun readUri(p: Parcel, name: String): BinderArg? {
        val start = p.dataPosition()
        p.setDataPosition(start)
        val marker = runCatching { p.readInt() }.getOrNull()
        p.setDataPosition(start)
        if (marker == 0) {
            p.readInt()
            return BinderArg.UriValue(name, null)
        }
        if (marker == 1) {
            p.readInt()
            tryParseUri(p, name)?.let { parsed ->
                if ((parsed as? BinderArg.UriValue)?.value != null) {
                    return parsed
                }
            }
            p.setDataPosition(start)
        }
        return tryParseUri(p, name)
    }

    private fun tryParseUri(p: Parcel, name: String): BinderArg? = runCatching {
        // Uri.CREATOR.createFromParcel internally uses readString8 on some Samsung ROMs,
        // truncating UTF-16LE parcel data at the first null byte. Read the type int
        // ourselves and use Uri.parse(readString()) for StringUri (type=1) so that
        // readString16 is called directly.
        when (p.readInt()) {
            0 -> BinderArg.UriValue(name, null)
            1 -> BinderArg.UriValue(name, p.readString()?.let { Uri.parse(it) })
            else -> {
                p.setDataPosition(p.dataPosition() - 4)
                BinderArg.UriValue(name, Uri.CREATOR.createFromParcel(p))
            }
        }
    }.getOrNull()

    private fun readIntent(p: Parcel, name: String): BinderArg? {
        val start = p.dataPosition()
        p.setDataPosition(start)
        val marker = runCatching { p.readInt() }.getOrNull()
        p.setDataPosition(start)
        if (marker == 0) {
            p.readInt()
            return BinderArg.IntentValue(name, null)
        }
        if (marker == 1) {
            p.readInt()
            runCatching { Intent.CREATOR.createFromParcel(p) }
                .getOrNull()
                ?.takeIf(::isMeaningfulIntent)
                ?.let { return BinderArg.IntentValue(name, it) }
            p.setDataPosition(start)
        }
        return runCatching { Intent.CREATOR.createFromParcel(p) }
            .getOrNull()
            ?.let { BinderArg.IntentValue(name, it) }
    }

    private fun isMeaningfulIntent(intent: Intent): Boolean {
        return intent.action != null ||
            intent.data != null ||
            intent.`package` != null ||
            intent.component != null ||
            !intent.categories.isNullOrEmpty()
    }
}
