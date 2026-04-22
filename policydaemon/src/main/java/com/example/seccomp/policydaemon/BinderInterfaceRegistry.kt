package com.example.seccomp.policydaemon

/**
 * Maps (interfaceDescriptor, transactionCode) → method name.
 *
 * Tries reflection on the AIDL Stub class first (works on userdebug builds with
 * hidden-API exemptions).  Falls back to a hardcoded table for common system
 * interfaces when reflection is blocked by the hidden-API policy.
 */
object BinderInterfaceRegistry {

    private val cache = HashMap<String, Map<Int, String>>()

    // Hardcoded codes for interfaces whose stubs are consistently inaccessible.
    // Codes are FIRST_CALL_TRANSACTION (= 1) + AIDL ordinal and are stable across
    // Android versions for these well-known interfaces.
    private val hardcoded: Map<String, Map<Int, String>> = mapOf(
        "android.content.IContentProvider" to mapOf(
            1 to "query",
            2 to "getType",
            3 to "insert",
            4 to "bulkInsert",
            5 to "delete",
            6 to "update",
            7 to "openFile",
            8 to "openAssetFile",
            9 to "getStreamTypes",
            10 to "openTypedAssetFile",
            11 to "createCancellationSignal",
            12 to "canonicalize",
            13 to "uncanonicalize",
            14 to "refresh",
            15 to "checkUriPermission",
        ),
        "android.app.IActivityManager" to mapOf(
            1 to "startActivity",
            2 to "startActivityAsUser",
            14 to "broadcastIntent",
            25 to "startService",
            27 to "bindService",
        ),
        "android.app.IActivityTaskManager" to mapOf(
            1 to "startActivity",
            2 to "startActivityAsUser",
        ),
    )

    fun methodName(interfaceDescriptor: String, transactionCode: Int): String? {
        val map = cache.getOrPut(interfaceDescriptor) { buildMap(interfaceDescriptor) }
        return map[transactionCode]
    }

    private fun buildMap(interfaceDescriptor: String): Map<Int, String> {
        hardcoded[interfaceDescriptor]?.let { known ->
            return known
        }
        val reflected = reflectMap(interfaceDescriptor)
        if (reflected.isNotEmpty()) return reflected
        return emptyMap()
    }

    private fun reflectMap(interfaceDescriptor: String): Map<Int, String> {
        return try {
            val stubClass = Class.forName("$interfaceDescriptor\$Stub")
            val result = mutableMapOf<Int, String>()
            for (field in stubClass.declaredFields) {
                val name = field.name
                if (name.startsWith("TRANSACTION_")) {
                    runCatching {
                        field.isAccessible = true
                        val code = field.getInt(null)
                        result[code] = name.removePrefix("TRANSACTION_")
                    }
                }
            }
            result
        } catch (_: Exception) {
            emptyMap()
        }
    }
}
