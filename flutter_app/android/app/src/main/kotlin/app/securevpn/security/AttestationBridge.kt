package app.securevpn.security

import android.content.Context
import android.util.Base64
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager
import com.google.android.play.core.integrity.StandardIntegrityManager.PrepareIntegrityTokenRequest
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenRequest
import io.flutter.plugin.common.MethodChannel

/**
 * Pillar 1 (Android): Play Integrity STANDARD request bound to a requestHash.
 *
 * Dart computes bindingHash = SHA-256(clientEphemeralPub ‖ serverChallenge) and
 * passes it here; we set it as the integrity `requestHash`. The decoded verdict
 * the backend receives carries requestDetails.requestHash == this value, so the
 * backend can prove the token was minted for THIS public key on a genuine
 * device. A swapped key produces a mismatching hash and is rejected server-side.
 *
 * Warm-up (prepareIntegrityToken) is done once and the provider cached — the
 * per-connect request() is then fast.
 */
class AttestationBridge(
    private val appContext: Context,
    private val cloudProjectNumber: Long,
) {
    private val manager: StandardIntegrityManager by lazy {
        IntegrityManagerFactory.createStandard(appContext)
    }

    @Volatile
    private var tokenProvider: StandardIntegrityManager.StandardIntegrityTokenProvider? = null

    /** Warm up at app start so the first connect isn't slow. Idempotent. */
    fun warmUp() {
        if (tokenProvider != null) return
        manager.prepareIntegrityToken(
            PrepareIntegrityTokenRequest.builder()
                .setCloudProjectNumber(cloudProjectNumber)
                .build(),
        ).addOnSuccessListener { provider -> tokenProvider = provider }
            .addOnFailureListener { /* retried lazily on demand */ }
    }

    /** Handle the Flutter `attest` call. [bindingHashB64] is base64 of 32 bytes. */
    fun attest(bindingHashB64: String, result: MethodChannel.Result) {
        val requestHash = toRequestHash(bindingHashB64)

        val provider = tokenProvider
        if (provider != null) {
            request(provider, requestHash, result)
            return
        }
        // Cold path: warm up, then request.
        manager.prepareIntegrityToken(
            PrepareIntegrityTokenRequest.builder()
                .setCloudProjectNumber(cloudProjectNumber)
                .build(),
        ).addOnSuccessListener { p ->
            tokenProvider = p
            request(p, requestHash, result)
        }.addOnFailureListener { e ->
            result.error("play_unavailable", e.message, null)
        }
    }

    private fun request(
        provider: StandardIntegrityManager.StandardIntegrityTokenProvider,
        requestHash: String,
        result: MethodChannel.Result,
    ) {
        provider.request(
            StandardIntegrityTokenRequest.builder()
                .setRequestHash(requestHash)
                .build(),
        ).addOnSuccessListener { token ->
            result.success(
                mapOf("platform" to "android", "integrityToken" to token.token()),
            )
        }.addOnFailureListener { e ->
            // A failed warm-up provider may be stale; drop it so next try re-preps.
            tokenProvider = null
            result.error("transient", e.message, null)
        }
    }

    /** requestHash must be URL-safe base64, no-wrap, ≤500 bytes. */
    private fun toRequestHash(bindingHashB64: String): String {
        val raw = Base64.decode(bindingHashB64, Base64.DEFAULT)
        return Base64.encodeToString(raw, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }
}
