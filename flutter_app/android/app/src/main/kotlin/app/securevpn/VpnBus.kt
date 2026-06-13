package app.securevpn

import android.os.Handler
import android.os.Looper
import io.flutter.plugin.common.EventChannel

/**
 * Tiny in-process bridge between [SingBoxVpnService] (which runs in the default
 * process) and the Flutter EventChannel sink owned by [MainActivity]. The
 * service can come up/down independently of the Activity, so we keep the last
 * state here and replay it when a sink attaches.
 *
 * All sink writes are marshalled to the main thread — EventChannel requires it.
 */
object VpnBus {
    enum class State { DISCONNECTED, CONNECTING, CONNECTED, DISCONNECTING, RECONNECTING, ERROR }

    @Volatile var currentState: State = State.DISCONNECTED
        private set

    private val main = Handler(Looper.getMainLooper())
    private var sink: EventChannel.EventSink? = null

    fun attach(s: EventChannel.EventSink) { sink = s }
    fun detach() { sink = null }

    fun emitState(state: State) {
        currentState = state
        post(mapOf("type" to "state", "state" to state.name.lowercase()))
    }

    fun emitTraffic(uploadBytes: Long, downloadBytes: Long, uploadSpeed: Long, downloadSpeed: Long) {
        post(
            mapOf(
                "type" to "traffic",
                "uploadBytes" to uploadBytes,
                "downloadBytes" to downloadBytes,
                "uploadSpeed" to uploadSpeed,
                "downloadSpeed" to downloadSpeed,
            ),
        )
    }

    private fun post(event: Map<String, Any?>) {
        val s = sink ?: return
        main.post { s.success(event) }
    }
}
