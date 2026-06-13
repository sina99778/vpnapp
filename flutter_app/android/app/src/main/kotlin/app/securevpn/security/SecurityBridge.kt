package app.securevpn.security

import io.flutter.plugin.common.MethodChannel

/**
 * Pillar 2 (Android): JNI front for the native anti-tamper sweep.
 *
 * The real checks live in C (libsecurity.so / tamper.c) and FAIL CLOSED by
 * abort() — so a positive detection typically never returns here at all; the
 * process dies with SIGABRT. [nativeAssertIntegrity] returns true only when the
 * environment looks clean.
 */
object SecurityBridge {
    init {
        // If the lib itself was tampered/removed, loading throws → caller treats
        // that as suspicious and fails closed.
        System.loadLibrary("security")
    }

    @JvmStatic external fun nativeAssertIntegrity(): Boolean
    @JvmStatic external fun nativeAntiDebugInit()

    /** Run the native sweep at startup; abort() inside native on hard signals. */
    fun assertAtStartup() {
        nativeAntiDebugInit()
        nativeAssertIntegrity()
    }

    /** Handle the Flutter `assertIntegrity` method. */
    fun handle(result: MethodChannel.Result) {
        val clean = runCatching { nativeAssertIntegrity() }.getOrDefault(false)
        result.success(clean)
    }
}
