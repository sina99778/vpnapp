import 'dart:convert';

/// Response from POST /connect (Provisioning Model). Carries NO usable VPN
/// config — only the grant + nonce the client needs to drive the ad flow.
class ConnectResponse {
  const ConnectResponse({
    required this.sessionId,
    required this.grantId,
    required this.nonce,
    required this.requiredAds,
    required this.provisioningExpiresAt,
    required this.serverNote,
  });

  /// The provisioning session id (status='provisioning', short TTL).
  final String sessionId;

  /// The connect grant this client must fulfil by watching [requiredAds] ads.
  final String grantId;

  /// Single-use value passed to AdMob as `customData`; the SSV callback returns
  /// it to the backend, binding each verified ad to THIS grant. Treat as opaque.
  final String nonce;

  final int requiredAds;

  /// Absolute server deadline; after this the provisioning session is reaped.
  final DateTime provisioningExpiresAt;

  /// Optional server-supplied display node label, country etc. (metadata only —
  /// never an address).
  final String? serverNote;

  factory ConnectResponse.fromJson(Map<String, dynamic> j) {
    return ConnectResponse(
      sessionId: j['sessionId'] as String,
      grantId: j['grantId'] as String,
      nonce: j['nonce'] as String,
      requiredAds: (j['requiredAds'] as num).toInt(),
      provisioningExpiresAt: DateTime.parse(j['provisioningExpiresAt'] as String).toUtc(),
      serverNote: j['serverNote'] as String?,
    );
  }
}

/// The AES-256-GCM envelope returned by /verify-ad-reward. All byte fields are
/// base64. Decryption contract is fixed by AppConfig.payloadAlg.
class EncryptedPayload {
  const EncryptedPayload({
    required this.alg,
    required this.serverPubKey,
    required this.iv,
    required this.cipherText,
    required this.tag,
  });

  final String alg;

  /// Server ephemeral X25519 public key (raw 32 bytes, base64) — `key_ref`.
  final List<int> serverPubKey;

  /// 96-bit GCM nonce (12 bytes).
  final List<int> iv;

  final List<int> cipherText;

  /// 128-bit GCM auth tag (16 bytes).
  final List<int> tag;

  factory EncryptedPayload.fromJson(Map<String, dynamic> j) {
    List<int> b64(String key) {
      final v = j[key];
      if (v is! String || v.isEmpty) {
        throw FormatException('missing payload field: $key');
      }
      try {
        return base64.decode(v);
      } on FormatException catch (e) {
        // Distinguish a malformed-base64 value from a missing field so
        // telemetry can tell "server sent garbage" from "field absent".
        throw FormatException('invalid base64 in payload field: $key', e.source);
      }
    }

    return EncryptedPayload(
      alg: j['alg'] as String? ?? '',
      serverPubKey: b64('keyRef'),
      iv: b64('iv'),
      cipherText: b64('ciphertext'),
      tag: b64('tag'),
    );
  }
}

/// Response from POST /verify-ad-reward once the grant is fulfilled. This is the
/// ONLY response that carries a usable (encrypted) config.
class VerifyRewardResponse {
  const VerifyRewardResponse({
    required this.sessionId,
    required this.expiresAt,
    required this.grantedMinutes,
    required this.payload,
  });

  final String sessionId;

  /// Absolute session expiry (server authority). The native engine also gets
  /// this so it can proactively tear down even if the panel is slow to drop.
  final DateTime expiresAt;

  final int grantedMinutes;

  /// Null on the idempotent replay path where the caller already holds config;
  /// present on first successful fulfilment.
  final EncryptedPayload? payload;

  factory VerifyRewardResponse.fromJson(Map<String, dynamic> j) {
    final p = j['payload'];
    return VerifyRewardResponse(
      sessionId: j['sessionId'] as String,
      expiresAt: DateTime.parse(j['expiresAt'] as String).toUtc(),
      grantedMinutes: (j['grantedMinutes'] as num?)?.toInt() ?? 0,
      payload: p is Map<String, dynamic> ? EncryptedPayload.fromJson(p) : null,
    );
  }
}

/// The decrypted, validated VPN profile handed to the native engine. We keep it
/// as the raw sing-box JSON string plus parsed expiry — the native side is the
/// authority on parsing, but we sanity-check it is JSON before crossing the
/// channel so we never feed garbage to the core.
class VpnProfile {
  const VpnProfile({required this.singboxConfigJson, required this.expiresAt});

  final String singboxConfigJson;
  final DateTime expiresAt;

  /// Validates that [plaintext] is a JSON object before trusting it. Throwing
  /// here keeps malformed/forged payloads out of the native core.
  factory VpnProfile.fromDecrypted(String plaintext, DateTime expiresAt) {
    final decoded = jsonDecode(plaintext);
    if (decoded is! Map<String, dynamic>) {
      throw const FormatException('config is not a JSON object');
    }
    // Minimal shape check — the native side does full validation.
    if (!decoded.containsKey('outbounds') && !decoded.containsKey('outbound')) {
      throw const FormatException('config has no outbound');
    }
    return VpnProfile(singboxConfigJson: plaintext, expiresAt: expiresAt);
  }
}
