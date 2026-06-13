import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../config/app_config.dart';
import '../errors/failures.dart';
import '../../shared/models/connection_models.dart';

/// A short-lived X25519 keypair the client generates at /connect time. The
/// PRIVATE key never leaves the device and is never persisted — it lives only
/// in memory for the ~5-minute provisioning window, giving per-session forward
/// secrecy. The PUBLIC key is sent to the backend (and bound into attestation).
class EphemeralSession {
  EphemeralSession._(this._keyPair, this.publicKeyBytes);

  final SimpleKeyPair _keyPair;

  /// Raw 32-byte X25519 public key to send to the backend at /connect.
  final Uint8List publicKeyBytes;

  String get publicKeyBase64 => base64.encode(publicKeyBytes);
}

/// Implements the client half of the payload encryption contract documented in
/// Phase 1 §6:
///   ikm  = X25519(clientPriv, serverEphPub)
///   key  = HKDF-SHA256(ikm, salt = sessionId, info = "vpncfg|v1", len = 32)
///   plain = AES-256-GCM-decrypt(key, iv, ciphertext, tag)
///
/// Pure Dart (no native crypto blob) so it survives obfuscation cleanly.
class PayloadCrypto {
  PayloadCrypto({
    X25519? x25519,
    AesGcm? aesGcm,
  })  : _x25519 = x25519 ?? X25519(),
        _aesGcm = aesGcm ?? AesGcm.with256bits();

  final X25519 _x25519;
  final AesGcm _aesGcm;

  /// Generate the per-session ephemeral keypair. Call once per /connect.
  Future<EphemeralSession> newEphemeralSession() async {
    final kp = await _x25519.newKeyPair();
    final pub = await kp.extractPublicKey();
    return EphemeralSession._(kp, Uint8List.fromList(pub.bytes));
  }

  /// Decrypt the server payload into a validated [VpnProfile], or throw a
  /// [PayloadFailure]. Any failure here is treated as a security event — we
  /// never return a partial/guessed config.
  Future<VpnProfile> decryptProfile({
    required EphemeralSession session,
    required EncryptedPayload payload,
    required String sessionId,
    required DateTime expiresAt,
  }) async {
    try {
      if (payload.alg != AppConfig.payloadAlg) {
        throw PayloadFailure('Unsupported payload algorithm.', cause: payload.alg);
      }
      _expectLen('server public key', payload.serverPubKey, 32);
      _expectLen('iv', payload.iv, 12);
      _expectLen('tag', payload.tag, 16);

      // Reject a server ephemeral key equal to our own — a sign of a reflected
      // key (bug or MITM) that would yield a degenerate shared secret.
      if (_constTimeEquals(payload.serverPubKey, session.publicKeyBytes)) {
        throw const PayloadFailure('Server key invalid (reflected).');
      }

      // 1) ECDH against the server's ephemeral public key.
      final serverPub = SimplePublicKey(payload.serverPubKey, type: KeyPairType.x25519);
      final sharedSecret = await _x25519.sharedSecretKey(
        keyPair: session._keyPair,
        remotePublicKey: serverPub,
      );

      // 2) HKDF-SHA256: salt = sessionId bytes, info = fixed context.
      final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
      final derived = await hkdf.deriveKey(
        secretKey: sharedSecret,
        nonce: utf8.encode(sessionId), // 'nonce' is HKDF salt in this package
        info: utf8.encode(AppConfig.payloadHkdfInfo),
      );

      // 3) AES-256-GCM. SecretBox keeps ciphertext / nonce / mac SEPARATE.
      final box = SecretBox(
        payload.cipherText,
        nonce: payload.iv,
        mac: Mac(payload.tag),
      );
      final clearBytes = await _aesGcm.decrypt(box, secretKey: derived);
      final plaintext = utf8.decode(clearBytes);

      // 4) Validate shape before it ever reaches the native core.
      return VpnProfile.fromDecrypted(plaintext, expiresAt);
    } on PayloadFailure {
      rethrow;
    } on SecretBoxAuthenticationError catch (e) {
      // Tag mismatch => tampered or wrong key. Hard security stop.
      throw PayloadFailure('Configuration failed integrity check.', cause: e);
    } on FormatException catch (e) {
      throw PayloadFailure('Configuration was malformed.', cause: e);
    } catch (e) {
      throw PayloadFailure('Could not establish a secure configuration.', cause: e);
    }
  }

  void _expectLen(String what, List<int> bytes, int len) {
    if (bytes.length != len) {
      throw PayloadFailure('Invalid $what length.', cause: '${bytes.length}!=$len');
    }
  }

  bool _constTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }
}
