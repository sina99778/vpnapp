package app.securevpn

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import app.securevpn.security.AttestationBridge
import app.securevpn.security.SecurityBridge
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.plugin.common.PluginRegistry.ActivityResultListener

/**
 * Flutter bridge for the VPN core. Mirrors the Dart SingboxVpnEngine contract:
 *   MethodChannel app.securevpn/vpn         — prepare / start / stop / status
 *   EventChannel  app.securevpn/vpn_events  — {type:'state'|'traffic', ...}
 *
 * This class owns ONLY the bridge + the OS consent dance. The actual tunnel
 * lives in [SingBoxVpnService]; state/traffic flow back through [VpnBus].
 *
 * Zero-Trust note: the config string handed to `start` is ALREADY decrypted by
 * Dart. Native never sees the encrypted payload or any backend token. We just
 * feed the config to the core and never log it.
 */
class MainActivity : FlutterActivity(), ActivityResultListener {

    private val methodChannelName = "app.securevpn/vpn"
    private val eventChannelName = "app.securevpn/vpn_events"
    private val attestChannelName = "app.securevpn/attest"
    private val securityChannelName = "app.securevpn/security"
    private val vpnPrepareRequest = 0x7A11

    private var eventSink: EventChannel.EventSink? = null
    private var pendingPrepareResult: Result? = null
    private lateinit var attestation: AttestationBridge

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        val messenger = flutterEngine.dartExecutor.binaryMessenger

        // ── Pillar 2: native anti-tamper sweep + anti-debug, at the earliest
        //    point we control. Aborts (SIGABRT) inside native on a hard signal. ──
        runCatching { SecurityBridge.assertAtStartup() }

        // ── Pillar 1: Play Integrity, warmed up so the first connect is fast. ──
        attestation = AttestationBridge(applicationContext, readCloudProjectNumber())
        attestation.warmUp()

        MethodChannel(messenger, methodChannelName).setMethodCallHandler { call, result ->
            when (call.method) {
                "prepare" -> handlePrepare(result)
                "start" -> handleStart(call.argument("config"),
                                        call.argument("sessionId"),
                                        call.argument("hardExpiryEpochMs"),
                                        result)
                "stop" -> { SingBoxVpnService.stop(this); result.success(null) }
                "status" -> result.success(VpnBus.currentState.name.lowercase())
                else -> result.notImplemented()
            }
        }

        MethodChannel(messenger, attestChannelName).setMethodCallHandler { call, result ->
            when (call.method) {
                "attest" -> {
                    val hash = call.argument<String>("bindingHash")
                    if (hash == null) result.error("bad_args", "missing bindingHash", null)
                    else attestation.attest(hash, result)
                }
                else -> result.notImplemented()
            }
        }

        MethodChannel(messenger, securityChannelName).setMethodCallHandler { call, result ->
            when (call.method) {
                "assertIntegrity" -> SecurityBridge.handle(result)
                else -> result.notImplemented()
            }
        }

        EventChannel(messenger, eventChannelName).setStreamHandler(
            object : EventChannel.StreamHandler {
                override fun onListen(args: Any?, sink: EventChannel.EventSink) {
                    eventSink = sink
                    // Replay current state to a fresh listener.
                    sink.success(mapOf("type" to "state", "state" to VpnBus.currentState.name.lowercase()))
                    VpnBus.attach(sink)
                }
                override fun onCancel(args: Any?) {
                    VpnBus.detach()
                    eventSink = null
                }
            },
        )
    }

    // --- OS consent --------------------------------------------------------

    private fun handlePrepare(result: Result) {
        // VpnService.prepare returns an Intent if the user must grant consent,
        // or null if already granted. We surface the grant decision to Dart.
        val intent: Intent? = VpnService.prepare(this)
        if (intent == null) {
            result.success(true)
            return
        }
        if (pendingPrepareResult != null) {
            result.error("already_pending", "A consent request is already in progress", null)
            return
        }
        pendingPrepareResult = result
        startActivityForResult(intent, vpnPrepareRequest)
    }

    /** Play Cloud project number from manifest <meta-data>, no gradle codegen. */
    private fun readCloudProjectNumber(): Long {
        val ai = packageManager.getApplicationInfo(packageName, PackageManager.GET_META_DATA)
        return ai.metaData?.get("play.cloud_project_number")?.toString()?.toLongOrNull() ?: 0L
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean {
        if (requestCode != vpnPrepareRequest) return false
        pendingPrepareResult?.success(resultCode == Activity.RESULT_OK)
        pendingPrepareResult = null
        return true
    }

    // --- start -------------------------------------------------------------

    private fun handleStart(config: String?, sessionId: String?, hardExpiryEpochMs: Long?, result: Result) {
        if (config.isNullOrBlank() || sessionId.isNullOrBlank()) {
            result.error("bad_config", "missing config or sessionId", null)
            return
        }
        // Consent must already be granted (Dart calls prepare first); re-check to
        // fail fast rather than crash the service.
        if (VpnService.prepare(this) != null) {
            result.error("consent_denied", "VPN consent not granted", null)
            return
        }
        SingBoxVpnService.start(this, sessionId, config, hardExpiryEpochMs ?: 0L)
        result.success(null)
    }
}
