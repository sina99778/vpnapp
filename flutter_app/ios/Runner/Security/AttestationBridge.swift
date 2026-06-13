import DeviceCheck
import Flutter
import Foundation

/// Pillar 1 (iOS): App Attest bound to a clientDataHash.
///
/// Dart computes bindingHash = SHA-256(clientEphemeralPub ‖ serverChallenge)
/// and passes it here. We feed it as the App Attest `clientDataHash`, so the
/// assertion the backend receives is cryptographically bound to THIS public
/// key. A swapped key yields a hash the server won't match → rejected.
///
/// First run per install: generateKey + attestKey (registers the Secure-Enclave
/// key with Apple; the backend stores the public key). Every run after: a fast
/// on-device generateAssertion with a strictly-increasing counter.
final class AttestationBridge {
    private let service = DCAppAttestService.shared
    private let keyIdDefault = "appattest.keyId"

    func attest(bindingHashB64: String, result: @escaping FlutterResult) {
        guard service.isSupported else {
            // Simulator / Mac Catalyst / unsupported device. The flow applies the
            // degraded-tier policy rather than hard-failing these clients.
            result(FlutterError(code: "unsupported", message: "App Attest unsupported", details: nil))
            return
        }
        // App Attest requires clientDataHash to be exactly 32 bytes (a SHA-256
        // digest); a wrong length yields .invalidInput and a confusing retry loop.
        guard let bindingHash = Data(base64Encoded: bindingHashB64), bindingHash.count == 32 else {
            result(FlutterError(code: "bad_args", message: "bindingHash must be 32 bytes", details: nil))
            return
        }

        if let keyId = UserDefaults.standard.string(forKey: keyIdDefault) {
            generateAssertion(keyId: keyId, clientDataHash: bindingHash, result: result)
        } else {
            firstTimeAttest(clientDataHash: bindingHash, result: result)
        }
    }

    // MARK: - First-time registration (generateKey → attestKey)

    private func firstTimeAttest(clientDataHash: Data, result: @escaping FlutterResult) {
        service.generateKey { [weak self] keyId, error in
            guard let self = self, let keyId = keyId, error == nil else {
                result(self?.mapError(error) ?? FlutterError(code: "unknown", message: nil, details: nil))
                return
            }
            self.service.attestKey(keyId, clientDataHash: clientDataHash) { attestation, attErr in
                guard let attestation = attestation, attErr == nil else {
                    // Per Apple: on any error other than serverUnavailable, discard
                    // the key. serverUnavailable ⇒ caller may retry the same key.
                    if !self.isServerUnavailable(attErr) {
                        UserDefaults.standard.removeObject(forKey: self.keyIdDefault)
                    }
                    result(self.mapError(attErr))
                    return
                }
                UserDefaults.standard.set(keyId, forKey: self.keyIdDefault)
                result([
                    "platform": "ios",
                    "mode": "attest",
                    "keyId": keyId,
                    "attestation": attestation.base64EncodedString(),
                ])
            }
        }
    }

    // MARK: - Per-connect assertion

    private func generateAssertion(keyId: String, clientDataHash: Data, result: @escaping FlutterResult) {
        service.generateAssertion(keyId, clientDataHash: clientDataHash) { [weak self] assertion, error in
            guard let self = self else { return }
            guard let assertion = assertion, error == nil else {
                // invalidKey ⇒ the stored key is gone (reinstall/restore). Drop it
                // so the next attempt re-registers via attestKey.
                if self.isInvalidKey(error) {
                    UserDefaults.standard.removeObject(forKey: self.keyIdDefault)
                }
                result(self.mapError(error))
                return
            }
            result([
                "platform": "ios",
                "mode": "assert",
                "keyId": keyId,
                "assertion": assertion.base64EncodedString(),
            ])
        }
    }

    // MARK: - Error mapping

    private func isServerUnavailable(_ error: Error?) -> Bool {
        (error as? DCError)?.code == .serverUnavailable
    }
    private func isInvalidKey(_ error: Error?) -> Bool {
        (error as? DCError)?.code == .invalidKey
    }

    private func mapError(_ error: Error?) -> FlutterError {
        guard let code = (error as? DCError)?.code else {
            return FlutterError(code: "unknown", message: error?.localizedDescription, details: nil)
        }
        switch code {
        case .featureUnsupported:
            return FlutterError(code: "unsupported", message: "unsupported", details: nil)
        case .serverUnavailable:
            return FlutterError(code: "transient", message: "server unavailable", details: nil)
        case .invalidInput, .invalidKey:
            return FlutterError(code: "transient", message: "retry", details: nil)
        default:
            return FlutterError(code: "transient", message: "attestation failed", details: nil)
        }
    }
}
