import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart' show CancelToken;

import '../../../core/crypto/payload_crypto.dart';
import '../../../core/errors/failures.dart';
import '../../../core/network/api_client.dart';
import '../../../core/security/attestation_service.dart';
import '../../../shared/models/connection_models.dart';

/// Talks to the middleware for the two connection endpoints and owns the
/// crypto handshake. Returns typed models; throws [AppFailure] on any error.
class ConnectionRepository {
  ConnectionRepository({
    required ApiClient api,
    required PayloadCrypto crypto,
    required AttestationService attestation,
  })  : _api = api,
        _crypto = crypto,
        _attest = attestation;

  final ApiClient _api;
  final PayloadCrypto _crypto;
  final AttestationService _attest;

  /// POST /connect — creates a provisioning session bound to a fresh ephemeral
  /// keypair AND a device attestation that binds that key. Returns the grant
  /// info AND the [EphemeralSession] whose private key the caller holds (in
  /// memory only) until verify.
  Future<({ConnectResponse response, EphemeralSession session})> connect({
    CancelToken? cancelToken,
  }) async {
    final session = await _crypto.newEphemeralSession();

    // 1) Get a one-time attestation challenge bound to this device.
    final challengeJson = await _api.postJson(
      '/api/v1/device/attest/challenge',
      cancelToken: cancelToken,
      body: {'purpose': 'connect'},
    );
    final challengeId = challengeJson['challengeId'] as String?;
    final challengeStr = challengeJson['challenge'] as String?;
    if (challengeId == null || challengeStr == null || challengeStr.isEmpty) {
      throw const AuthFailure('Server returned an incomplete challenge.');
    }
    final Uint8List challenge;
    try {
      challenge = base64.decode(challengeStr);
    } on FormatException catch (e) {
      throw AuthFailure('Server challenge was malformed.', cause: e);
    }

    // 2) Produce the attestation bound to (clientPubKey ‖ challenge). A swapped
    //    key fails server-side verification — this is the Phase-1 crux.
    final attestation = await _attest.attest(
      clientPublicKey: Uint8List.fromList(session.publicKeyBytes),
      challenge: Uint8List.fromList(challenge),
    );

    // 3) Verify the attestation server-side. This is what flips devices.is_attested
    //    and binds this exact public key — it MUST happen before /connect, which
    //    is gated by the backend's AttestedGuard (is_attested + key match).
    await _api.postJson(
      '/api/v1/device/attest/verify',
      cancelToken: cancelToken,
      body: {
        'challengeId': challengeId,
        'clientPublicKey': session.publicKeyBase64,
        'attestation': attestation.toJson(),
      },
    );

    // 4) /connect now carries ONLY the pubkey; the AttestedGuard checks it
    //    against the key just bound at verify.
    final json = await _api.postJson(
      '/api/v1/connect',
      cancelToken: cancelToken,
      body: {'clientPublicKey': session.publicKeyBase64},
    );
    return (response: ConnectResponse.fromJson(json), session: session);
  }

  /// POST /verify-ad-reward — claims the fulfilled grant. On success the backend
  /// returns the encrypted payload, which we decrypt locally into a [VpnProfile].
  /// Decryption failures are surfaced as PayloadFailure (fail closed).
  Future<VpnProfile> verifyAndDecrypt({
    required String grantId,
    required String sessionId,
    required EphemeralSession session,
    CancelToken? cancelToken,
  }) async {
    final json = await _api.postJson(
      '/api/v1/ads/verify-ad-reward', // backend AdsController is @Controller('ads')
      cancelToken: cancelToken,
      body: {
        'grantId': grantId,
        'sessionId': sessionId,
      },
    );

    // A malformed/garbage payload body must fail closed as a PayloadFailure,
    // not bubble up as an unexpected error.
    final VerifyRewardResponse verify;
    try {
      verify = VerifyRewardResponse.fromJson(json);
    } on FormatException catch (e) {
      throw PayloadFailure('Server returned a malformed configuration.', cause: e);
    } on TypeError catch (e) {
      throw PayloadFailure('Server returned an unexpected configuration shape.', cause: e);
    }

    final payload = verify.payload;
    if (payload == null) {
      // Idempotent replay without payload, or a server contract violation —
      // either way we have nothing to start with. Fail closed.
      throw const PayloadFailure('Server did not return a configuration.');
    }

    return _crypto.decryptProfile(
      session: session,
      payload: payload,
      sessionId: verify.sessionId,
      expiresAt: verify.expiresAt,
    );
  }
}
