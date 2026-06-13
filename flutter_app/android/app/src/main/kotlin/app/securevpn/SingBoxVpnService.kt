package app.securevpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import io.nekohasekai.libbox.BoxService
import io.nekohasekai.libbox.CommandClient
import io.nekohasekai.libbox.CommandClientHandler
import io.nekohasekai.libbox.CommandClientOptions
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.SetupOptions
import io.nekohasekai.libbox.StatusMessage
import io.nekohasekai.libbox.TunOptions
import kotlin.concurrent.thread

/**
 * The actual tunnel. Extends Android [VpnService] AND implements libbox's
 * [PlatformInterface] — libbox calls back into [openTun] during
 * [BoxService.start] to obtain the TUN file descriptor we build here.
 *
 * Lifecycle: started as a foreground service (mandatory on API 26+). The
 * decrypted config arrives via Intent extras (handed over from the Flutter
 * MethodChannel). We never persist or log the config; it lives for the session.
 */
class SingBoxVpnService : VpnService(), PlatformInterface {

    private var box: BoxService? = null
    private var commandClient: CommandClient? = null
    private var tunFd: ParcelFileDescriptor? = null
    private val mainHandler = Handler(Looper.getMainLooper())
    private var expiryRunnable: Runnable? = null

    // -----------------------------------------------------------------------
    // Service lifecycle
    // -----------------------------------------------------------------------
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> { stopSelfGracefully(); return START_NOT_STICKY }
            else -> {
                val config = intent?.getStringExtra(EXTRA_CONFIG)
                val expiry = intent?.getLongExtra(EXTRA_EXPIRY, 0L) ?: 0L
                // Strip the credential-bearing config from the Intent immediately so
                // it can't be recovered later via reflection/debugger on the held
                // Intent. We keep only the local `config` ref for the duration of start.
                intent?.removeExtra(EXTRA_CONFIG)
                if (config.isNullOrBlank()) { stopSelf(); return START_NOT_STICKY }
                goForeground()
                startCore(config, expiry)
            }
        }
        // We do NOT want START_STICKY: a system restart must not silently re-up a
        // tunnel whose session has likely expired. Reconnect is a user action.
        return START_NOT_STICKY
    }

    private fun startCore(config: String, hardExpiryEpochMs: Long) {
        VpnBus.emitState(VpnBus.State.CONNECTING)
        thread(name = "singbox-start") {
            try {
                ensureSetupOnce(applicationContext)
                // libbox parses the config and, during start(), calls openTun()
                // below to get our TUN fd.
                val service = Libbox.newService(config, this)
                service.start()
                box = service
                startCommandClient()
                scheduleHardExpiry(hardExpiryEpochMs)
                VpnBus.emitState(VpnBus.State.CONNECTED)
            } catch (t: Throwable) {
                // Never echo the config in the error.
                VpnBus.emitState(VpnBus.State.ERROR)
                stopSelfGracefully()
            }
        }
    }

    override fun onDestroy() {
        teardown()
        super.onDestroy()
    }

    override fun onRevoke() {
        // User/another VPN revoked our permission — tear down immediately.
        stopSelfGracefully()
    }

    private fun stopSelfGracefully() {
        VpnBus.emitState(VpnBus.State.DISCONNECTING)
        teardown()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        VpnBus.emitState(VpnBus.State.DISCONNECTED)
    }

    private fun teardown() {
        expiryRunnable?.let { mainHandler.removeCallbacks(it) }
        expiryRunnable = null
        runCatching { commandClient?.disconnect() }
        commandClient = null
        runCatching { box?.close() }
        box = null
        runCatching { tunFd?.close() }
        tunFd = null
    }

    // -----------------------------------------------------------------------
    // PlatformInterface — libbox drives these
    // -----------------------------------------------------------------------

    /** Build the TUN from libbox's resolved options and return its raw fd. */
    override fun openTun(options: TunOptions): Int {
        val builder = Builder().setSession("SecureVPN").setMtu(options.getMTU())

        val v4 = options.getInet4Address()
        while (v4.hasNext()) { val p = v4.next(); builder.addAddress(p.address, p.prefix) }
        val v6 = options.getInet6Address()
        while (v6.hasNext()) { val p = v6.next(); builder.addAddress(p.address, p.prefix) }

        if (options.getAutoRoute()) {
            // Route everything; the core's own sockets are excluded via protect().
            builder.addRoute("0.0.0.0", 0)
            builder.addRoute("::", 0)
        }

        runCatching {
            // NOTE: confirm the StringBox accessor (.value) against the generated
            // AAR; some libbox builds expose getValue().
            builder.addDnsServer(options.getDNSServerAddress().value)
        }

        // Exclude our own app so its sockets don't loop back through the tunnel.
        runCatching { builder.addDisallowedApplication(packageName) }

        val pfd = builder.establish() ?: throw IllegalStateException("VpnService.establish() returned null")
        tunFd = pfd
        return pfd.detachFd() // hand the raw fd to libbox; we keep pfd to close later
    }

    /** libbox asks us to protect a socket (exclude from the tunnel). */
    override fun autoDetectInterfaceControl(fd: Int) {
        if (!protect(fd)) throw IllegalStateException("protect($fd) failed")
    }

    override fun usePlatformAutoDetectInterfaceControl(): Boolean = true
    override fun useProcFS(): Boolean = false
    override fun writeLog(message: String) { /* intentionally minimal; never echo config */ }

    // Remaining PlatformInterface members are not needed for our outbound-only
    // client; return safe defaults / throw "unsupported" as appropriate.
    override fun findConnectionOwner(
        ipProto: Int, srcIp: String, srcPort: Int, destIp: String, destPort: Int,
    ): Int = throw UnsupportedOperationException()
    override fun packageNameByUid(uid: Int): String = throw UnsupportedOperationException()
    override fun uidByPackageName(packageName: String): Int = throw UnsupportedOperationException()

    // -----------------------------------------------------------------------
    // Status / traffic → EventChannel (via VpnBus)
    // -----------------------------------------------------------------------
    private fun startCommandClient() {
        val handler = object : CommandClientHandler {
            override fun connected() {}
            override fun disconnected(message: String?) {}
            override fun writeStatus(message: StatusMessage) {
                VpnBus.emitTraffic(
                    uploadBytes = message.uplinkTotal,
                    downloadBytes = message.downlinkTotal,
                    uploadSpeed = message.uplink,
                    downloadSpeed = message.downlink,
                )
            }
            // Other CommandClientHandler callbacks (logs, groups, clash mode) are
            // unused by this client.
        }
        val options = CommandClientOptions().apply {
            command = Libbox.CommandStatus
            statusInterval = 1_000_000_000L // 1s in nanoseconds; native already coalesces
        }
        commandClient = CommandClient(handler, options).also {
            runCatching { it.connect() }.onFailure {
                // Traffic stats are non-critical; the tunnel is already up. Log so a
                // silent "no traffic events" symptom is diagnosable rather than mysterious.
                android.util.Log.w("SingBoxVpnService", "command client connect failed: ${it.message}")
            }
        }
    }

    // -----------------------------------------------------------------------
    // Hard expiry — self-terminate exactly at the server deadline even if the
    // panel is slow to drop the ephemeral credential.
    // -----------------------------------------------------------------------
    private fun scheduleHardExpiry(epochMs: Long) {
        if (epochMs <= 0L) return
        val delay = epochMs - System.currentTimeMillis()
        if (delay <= 0L) { stopSelfGracefully(); return }
        val r = Runnable { stopSelfGracefully() }
        expiryRunnable = r
        mainHandler.postDelayed(r, delay)
    }

    private fun goForeground() {
        val channelId = "vpn"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val mgr = getSystemService(NotificationManager::class.java)
            if (mgr.getNotificationChannel(channelId) == null) {
                mgr.createNotificationChannel(
                    NotificationChannel(channelId, "VPN", NotificationManager.IMPORTANCE_LOW),
                )
            }
        }
        val tap = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notification: Notification = Notification.Builder(this, channelId)
            .setContentTitle("Secure VPN")
            .setContentText("Connected")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setContentIntent(tap)
            .build()
        startForeground(NOTIF_ID, notification)
    }

    companion object {
        private const val EXTRA_CONFIG = "config"
        private const val EXTRA_SESSION = "sessionId"
        private const val EXTRA_EXPIRY = "hardExpiryEpochMs"
        private const val ACTION_STOP = "app.securevpn.STOP"
        private const val NOTIF_ID = 0x5

        @Volatile private var didSetup = false

        /** Libbox.setup must run exactly once per process. */
        @Synchronized
        private fun ensureSetupOnce(context: Context) {
            if (didSetup) return
            val base = context.filesDir.absolutePath
            Libbox.setup(
                SetupOptions().apply {
                    basePath = base
                    workingPath = context.getDir("singbox", Context.MODE_PRIVATE).absolutePath
                    tempPath = context.cacheDir.absolutePath
                },
            )
            didSetup = true
        }

        fun start(context: Context, sessionId: String, config: String, hardExpiryEpochMs: Long) {
            val i = Intent(context, SingBoxVpnService::class.java)
                .putExtra(EXTRA_SESSION, sessionId)
                .putExtra(EXTRA_CONFIG, config)
                .putExtra(EXTRA_EXPIRY, hardExpiryEpochMs)
            context.startForegroundService(i)
        }

        fun stop(context: Context) {
            context.startService(Intent(context, SingBoxVpnService::class.java).setAction(ACTION_STOP))
        }
    }
}
