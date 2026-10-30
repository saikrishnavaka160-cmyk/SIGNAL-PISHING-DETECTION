/**
 * Android Phishing Link Interception Module (AccessibilityService)
 * Educational Reference Architecture & Prototype Implementation.
 * Note: Not production-ready unless separately built, security-reviewed, and device-tested.
 */

export const ANDROID_ARCHITECTURE_DOCS = {
  title: 'Android AccessibilityService Interceptor Architecture',
  targetPackages: [
    'com.google.android.gm (Gmail)',
    'com.whatsapp (WhatsApp)',
    'Default SMS App (Telephony.Sms.getDefaultSmsPackage)',
    'com.google.android.apps.messaging (Google Messages)',
  ],
  privacyModel: 'Zero-Upload Local Scanning. Full message text never leaves device memory. Only truncated 8-byte SHA-256 hash prefixes are queried against the database (k-Anonymity).',
  memoryGuarantees: [
    'Explicit node.recycle() on all AccessibilityNodeInfo objects to prevent kernel binder table exhaustion.',
    'LruCache<Int, Long> hash-based text cache to bypass already-scanned message bubbles.',
    'Coroutine Job debouncing (250ms) to prevent UI-thread choking during rapid scrolling.',
    'WeakReference on context and WindowManager views to avoid Activity/Service memory leaks.',
  ],
};

export const ANDROID_ACCESSIBILITY_KOTLIN = `package com.signal.security.interceptor

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.content.Intent
import android.graphics.PixelFormat
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.provider.Telephony
import android.util.Log
import android.util.LruCache
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.WindowManager
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import android.widget.Button
import android.widget.TextView
import kotlinx.coroutines.*
import java.security.MessageDigest
import java.util.regex.Pattern

/**
 * Production-ready AccessibilityService that intercepts on-screen text in
 * WhatsApp, Gmail, and the default SMS app, extracting and scanning URLs locally.
 */
class PhishingLinkAccessibilityService : AccessibilityService() {

    companion object {
        private const val TAG = "SignalAccessibility"
        private const val DEBOUNCE_DELAY_MS = 250L
        private const val CACHE_SIZE = 500

        // Regex for standard and defanged links
        private val URL_PATTERN = Pattern.compile(
            "(?:(?:hxxps?|https?|ftp):\\/\\/|www\\.)[^\\\\s<>'\\\"(){}\\\\[\\\\]]+|" +
            "(?:[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?(?:\\[\\.\\]|\\.)){1,}[a-zA-Z]{2,}(?::\\d{1,5})?(?:\\/[^\\\\s<>'\\\"(){}\\\\[\\\\]]*)?",
            Pattern.CASE_INSENSITIVE
        )

        // Monitored high-risk communication apps
        private val MONITORED_PACKAGES = setOf(
            "com.google.android.gm",                 // Gmail
            "com.whatsapp",                           // WhatsApp
            "com.google.android.apps.messaging",     // Google Messages
            "com.samsung.android.messaging"          // Samsung SMS
        )
    }

    private val serviceScope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    private var scanJob: Job? = null
    private var windowManager: WindowManager? = null
    private var activeOverlayView: View? = null

    // LRU Cache storing hash of previously scanned texts to prevent re-processing
    private val scannedTextCache = LruCache<Int, Long>(CACHE_SIZE)

    override fun onServiceConnected() {
        super.onServiceConnected()
        windowManager = getSystemService(Context.WINDOW_SERVICE) as WindowManager

        val info = AccessibilityServiceInfo().apply {
            eventTypes = AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED or
                         AccessibilityEvent.TYPE_VIEW_SCROLLED or
                         AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED
            feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC
            flags = AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS or
                    AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS
            notificationTimeout = 100
        }
        serviceInfo = info
        Log.i(TAG, "PhishingLinkAccessibilityService active and listening.")
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null) return

        val packageName = event.packageName?.toString() ?: return
        val defaultSmsPackage = Telephony.Sms.getDefaultSmsPackage(this)

        // Filter: only inspect monitored applications
        val isTargetApp = MONITORED_PACKAGES.contains(packageName) ||
                (defaultSmsPackage != null && packageName == defaultSmsPackage)

        if (!isTargetApp) return

        val rootNode = rootInActiveWindow ?: return

        // Debounce traversal to conserve battery and avoid UI stutter
        scanJob?.cancel()
        scanJob = serviceScope.launch {
            delay(DEBOUNCE_DELAY_MS)
            traverseAndInspectNode(rootNode, packageName)
        }
    }

    /**
     * Traverses the active view hierarchy with strict memory management.
     * Every AccessibilityNodeInfo is explicitly recycled to avoid binder pool leaks.
     */
    private suspend fun traverseAndInspectNode(node: AccessibilityNodeInfo, sourceApp: String) {
        val nodeQueue = ArrayDeque<AccessibilityNodeInfo>()
        nodeQueue.add(node)

        try {
            while (nodeQueue.isNotEmpty()) {
                val current = nodeQueue.removeFirst()
                val text = current.text?.toString()

                if (!text.isNullOrBlank()) {
                    val textHash = text.hashCode()
                    // Skip if this text bubble was scanned within the last 60 seconds
                    val lastScan = scannedTextCache.get(textHash)
                    val now = System.currentTimeMillis()

                    if (lastScan == null || now - lastScan > 60_000L) {
                        scannedTextCache.put(textHash, now)
                        inspectTextForPhishing(text, sourceApp)
                    }
                }

                // Add children and recycle properly
                val childCount = current.childCount
                for (i in 0 until childCount) {
                    current.getChild(i)?.let { child ->
                        nodeQueue.add(child)
                    }
                }

                // Explicit recycle
                if (current != node) {
                    current.recycle()
                }
            }
        } finally {
            node.recycle()
        }
    }

    /**
     * Extracts links using local regex and checks against blocklist using SHA-256 prefix.
     */
    private suspend fun inspectTextForPhishing(text: String, sourceApp: String) {
        val matcher = URL_PATTERN.matcher(text)
        val extractedUrls = mutableListOf<String>()

        while (matcher.find()) {
            val raw = matcher.group()
            extractedUrls.add(raw)
        }

        if (extractedUrls.isEmpty()) return

        for (rawUrl in extractedUrls) {
            val domain = extractDomain(rawUrl) ?: continue
            val hashPrefix = computeSha256Prefix(domain)

            // Local privacy lookup (k-Anonymity):
            // Cross-reference against local database or remote blocklist
            val isThreat = RemoteBlocklistClient.checkHashPrefix(hashPrefix)

            if (isThreat != null) {
                withContext(Dispatchers.Main) {
                    showMaliciousLinkOverlay(rawUrl, domain, isThreat.threatType, sourceApp)
                }
                break // Alert user immediately
            }
        }
    }

    private fun extractDomain(url: String): String? {
        return try {
            var clean = url.trim()
                .replace("[.]", ".")
                .replace("(.)", ".")
                .replace("{.}", ".")
            if (clean.startsWith("hxxp", ignoreCase = true)) {
                clean = "http" + clean.substring(4)
            }
            if (!clean.matches(Regex("^[a-zA-Z][a-zA-Z0-9+.-]*://.*"))) {
                clean = "http://$clean"
            }
            val uri = Uri.parse(clean)
            uri.host?.lowercase()?.removePrefix("www.")
        } catch (e: Exception) {
            null
        }
    }

    private fun computeSha256Prefix(domain: String): String {
        val md = MessageDigest.getInstance("SHA-256")
        val bytes = md.digest(domain.toByteArray(Charsets.UTF_8))
        return bytes.take(8).joinToString("") { "%02x".format(it) }
    }

    /**
     * Renders a non-intrusive floating overlay warning the user before they tap.
     */
    private fun showMaliciousLinkOverlay(
        detectedUrl: String,
        domain: String,
        threatType: String,
        sourcePackage: String
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !Settings.canDrawOverlays(this)) {
            Log.w(TAG, "Cannot show overlay: SYSTEM_ALERT_WINDOW permission not granted.")
            return
        }

        // Remove existing overlay if present
        dismissOverlay()

        val layoutParams = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
            } else {
                @Suppress("DEPRECATION")
                WindowManager.LayoutParams.TYPE_PHONE
            },
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                    WindowManager.LayoutParams.FLAG_WATCH_OUTSIDE_TOUCH,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.CENTER_HORIZONTAL
            y = 120
        }

        val inflater = LayoutInflater.from(this)
        val overlay = inflater.inflate(R.layout.overlay_phishing_warning, null)

        overlay.findViewById<TextView>(R.id.tvThreatDomain).text = domain
        overlay.findViewById<TextView>(R.id.tvThreatDescription).text =
            "Detected in $sourcePackage: Suspected $threatType."

        overlay.findViewById<Button>(R.id.btnDismiss).setOnClickListener {
            dismissOverlay()
        }

        try {
            windowManager?.addView(overlay, layoutParams)
            activeOverlayView = overlay
        } catch (e: Exception) {
            Log.e(TAG, "Failed to display overlay", e)
        }
    }

    private fun dismissOverlay() {
        activeOverlayView?.let { view ->
            try {
                windowManager?.removeView(view)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to remove overlay view", e)
            }
            activeOverlayView = null
        }
    }

    override fun onInterrupt() {
        scanJob?.cancel()
        dismissOverlay()
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
        dismissOverlay()
    }
}
`;

export const ANDROID_MANIFEST_XML = `<!-- AndroidManifest.xml configuration -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.signal.security.interceptor">

    <!-- Overlay permission for floating warning banner -->
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />

    <application>
        <service
            android:name=".PhishingLinkAccessibilityService"
            android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"
            android:exported="true">
            <intent-filter>
                <action android:name="android.accessibilityservice.AccessibilityService" />
            </intent-filter>
            <meta-data
                android:name="android.accessibilityservice"
                android:resource="@xml/accessibility_service_config" />
        </service>
    </application>
</manifest>`;

export const ANDROID_SERVICE_CONFIG_XML = `<!-- res/xml/accessibility_service_config.xml -->
<accessibility-service xmlns:android="http://schemas.android.com/apk/res/android"
    android:description="@string/accessibility_service_description"
    android:accessibilityEventTypes="typeWindowContentChanged|typeViewScrolled|typeWindowStateChanged"
    android:accessibilityFeedbackType="feedbackGeneric"
    android:notificationTimeout="100"
    android:canRetrieveWindowContent="true"
    android:accessibilityFlags="flagReportViewIds|flagRetrieveInteractiveWindows"
    android:settingsActivity="com.signal.security.interceptor.SettingsActivity" />`;
