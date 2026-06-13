import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter/services.dart';

import '../errors/failures.dart';

/// The Phase-1 crux, client side. Binds the per-session ECDH public key into
/// the device attestation so a rooted client cannot substitute its own key and
/// decrypt the config:
///
///   bindingHash = SHA-256( clientEphemeralPubKey ‖ serverChallenge )
///
/// On Android this becomes the Play Integrity STANDARD `requestHash`; on iOS it
/// becomes the App Attest `clientDataHash`. The backend recomputes the same
/// hash from the submitted public key + the challenge it issued, and rejects
/// any attestation whose bound hash doesn't match. A swapped key fails here,
/// before it ever reaches the payload key derivation.
class AttestationService {
  AttestationService([MethodChannel? channel])
      : _channel = channel ?? const MethodChannel('app.securevpn/attest');

  final MethodChannel _channel;

  /// Produce a platform attestation bound to [clientPublicKey] + [challenge].
  /// Returns an opaque map the backend knows how to verify. Throws
  /// [AuthFailure] on any attestation error (we fail closed — no token, no
  /// connection).
  Future<AttestationResult> attest({
    required Uint8List clientPublicKey,
    required Uint8List challenge,
  }) async {
    // Fail fast with a precise error rather than computing a bogus hash that the
    // platform/backend would reject opaquely.
    if (clientPublicKey.length != 32) {
      throw AuthFailure('Invalid public key length (${clientPublicKey.length}).');
    }
    if (challenge.length < 16) {
      throw AuthFailure('Challenge too short (${challenge.length}).');
    }
    final bindingHash = _bindingHash(clientPublicKey, challenge);
    try {
      final res = await _channel.invokeMapMethod<String, dynamic>('attest', {
        // Standard base64 of the raw 32-byte hash. Each platform converts as it
        // needs — DON'T "simplify" to base64url here: iOS decodes this straight
        // to the 32-byte clientDataHash, while Android re-encodes it as base64url
        // for Play Integrity's requestHash. One wire format, two consumers.
        'bindingHash': base64.encode(bindingHash),
      });
      if (res == null) throw const AuthFailure('Attestation returned nothing.');
      return AttestationResult.fromMap(Map<String, dynamic>.from(res));
    } on PlatformException catch (e) {
      // featureUnsupported (simulator/Mac), no-Play-Services, transient errors —
      // surface distinctly so the flow can apply the degraded-tier policy.
      throw AuthFailure(_message(e.code), cause: e);
    }
  }

  /// SHA-256(pub ‖ challenge). MUST match the backend's recomputation exactly.
  Uint8List _bindingHash(Uint8List pub, Uint8List challenge) {
    final buf = BytesBuilder(copy: false)
      ..add(pub)
      ..add(challenge);
    return Uint8List.fromList(crypto.sha256.convert(buf.toBytes()).bytes);
  }

  String _message(String code) => switch (code) {
        'unsupported' => 'This device cannot be verified (attestation unsupported).',
        'play_unavailable' => 'Google Play services are required.',
        'transient' => 'Verification temporarily unavailable. Try again.',
        _ => 'Device verification failed.',
      };
}

/// Opaque, platform-tagged attestation payload sent to /connect.
/// Android: {platform:'android', integrityToken}.
/// iOS:     {platform:'ios', mode:'attest'|'assert', keyId, attestation?|assertion}.
class AttestationResult {
  const AttestationResult(this.platform, this.data);
  final String platform;
  final Map<String, dynamic> data;

  factory AttestationResult.fromMap(Map<String, dynamic> m) {
    final platform = m['platform'] as String? ?? '';
    if (platform != 'android' && platform != 'ios') {
      throw const AuthFailure('Unknown attestation platform.');
    }
    return AttestationResult(platform, m);
  }

  Map<String, dynamic> toJson() => data;
}
