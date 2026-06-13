import 'dart:async';

import 'package:dio/dio.dart' show CancelToken;

import '../../../core/config/app_config.dart';
import '../../../core/crypto/payload_crypto.dart';
import '../../../core/errors/failures.dart';
import '../../../shared/models/connection_models.dart';
import '../../ads/domain/ad_reward_service.dart';
import '../../vpn/domain/vpn_engine_service.dart';
import '../data/connection_repository.dart';

/// The phases the user moves through. The UI renders off this enum; it is a
/// strict superset of the happy path so errors and cancellation are first-class.
enum ConnectionPhase {
  idle,
  requestingGrant, // POST /connect
  showingAds, // watching the N rewarded ads
  verifying, // POST /verify-ad-reward + decrypt
  preparing, // OS VPN consent
  starting, // handing config to the native core
  connected,
  disconnecting,
  failed,
}

/// Immutable snapshot of the flow for the UI.
class ConnectionFlowState {
  const ConnectionFlowState({
    required this.phase,
    this.adsWatched = 0,
    this.adsRequired = AppConfig.defaultRequiredAds,
    this.expiresAt,
    this.failure,
  });

  final ConnectionPhase phase;
  final int adsWatched;
  final int adsRequired;
  final DateTime? expiresAt;
  final AppFailure? failure;

  bool get isBusy =>
      phase != ConnectionPhase.idle &&
      phase != ConnectionPhase.connected &&
      phase != ConnectionPhase.failed;

  ConnectionFlowState copyWith({
    ConnectionPhase? phase,
    int? adsWatched,
    int? adsRequired,
    DateTime? expiresAt,
    AppFailure? failure,
    bool clearFailure = false,
  }) {
    return ConnectionFlowState(
      phase: phase ?? this.phase,
      adsWatched: adsWatched ?? this.adsWatched,
      adsRequired: adsRequired ?? this.adsRequired,
      expiresAt: expiresAt ?? this.expiresAt,
      failure: clearFailure ? null : (failure ?? this.failure),
    );
  }

  static const initial = ConnectionFlowState(phase: ConnectionPhase.idle);
}

/// Orchestrates: /connect → show N ads (nonce-bound) → /verify-ad-reward →
/// decrypt → prepare → start VPN. Emits [ConnectionFlowState] for the UI.
///
/// Zero-Trust posture baked in:
///   • The client never decides entitlement or "ad watched" — it shows ads,
///     then asks the backend to verify; verify only succeeds once the SSV
///     callbacks have landed server-side.
///   • The decrypted config is shape-checked before it touches the native core.
///   • Every external step is cancellable and fails closed (no tunnel on doubt).
class ConnectionFlowController {
  ConnectionFlowController({
    required ConnectionRepository repository,
    required AdRewardService ads,
    required VpnEngineService vpn,
    required String userId,
    void Function(ConnectionFlowState state)? onState,
  })  : _repo = repository,
        _ads = ads,
        _vpn = vpn,
        _userId = userId,
        _onState = onState;

  final ConnectionRepository _repo;
  final AdRewardService _ads;
  final VpnEngineService _vpn;
  final String _userId;
  final void Function(ConnectionFlowState)? _onState;

  /// Sentinel nonce for the best-effort closing ad. The backend MUST treat this
  /// value as never-grantable so a stray SSV callback can't fund any grant.
  static const String closingAdNonce = 'closing-session-no-grant';

  ConnectionFlowState _state = ConnectionFlowState.initial;
  ConnectionFlowState get state => _state;

  bool _cancelled = false;
  CancelToken? _cancelToken;

  /// Atomic re-entrancy guard: a second connect() returns the in-flight future
  /// instead of spawning a duplicate flow.
  Future<void>? _inFlight;

  void _emit(ConnectionFlowState s) {
    _state = s;
    _onState?.call(s);
  }

  /// Run the whole flow. A concurrent call joins the in-flight run.
  Future<void> connect() {
    final running = _inFlight;
    if (running != null) return running;
    final future = _runConnect();
    _inFlight = future;
    return future.whenComplete(() => _inFlight = null);
  }

  Future<void> _runConnect() async {
    _cancelled = false;
    _cancelToken = CancelToken();
    _emit(const ConnectionFlowState(phase: ConnectionPhase.requestingGrant).copyWith(clearFailure: true));

    try {
      // 1) /connect → provisioning session + grant + nonce + ephemeral keys.
      final connectResult = await _repo.connect(cancelToken: _cancelToken);
      final grant = connectResult.response;
      final EphemeralSession session = connectResult.session;
      _guardWindow(grant.provisioningExpiresAt);
      _throwIfCancelled();

      _emit(_state.copyWith(
        phase: ConnectionPhase.showingAds,
        adsRequired: grant.requiredAds,
        adsWatched: 0,
      ));

      // 2) Show exactly requiredAds rewarded ads, each carrying the SAME nonce
      //    so every SSV callback binds to THIS grant. We count locally only for
      //    UI progress — the backend counts the trusted SSV callbacks.
      for (var i = 0; i < grant.requiredAds; i++) {
        _guardWindow(grant.provisioningExpiresAt);
        _throwIfCancelled();

        final pres = await _ads.showRewarded(nonce: grant.nonce, userId: _userId);
        if (!pres.completed) {
          throw const AdFailure('Ad was not completed.', kind: AdFailureKind.dismissedEarly);
        }
        _emit(_state.copyWith(adsWatched: i + 1));
      }

      // 3) /verify-ad-reward → decrypt. The backend rejects this until it has
      //    seen all SSV callbacks, so a skipped/forged ad simply 409s here.
      _emit(_state.copyWith(phase: ConnectionPhase.verifying));
      final profile = await _verifyWithRetry(
        grantId: grant.grantId,
        sessionId: grant.sessionId,
        session: session,
        deadline: grant.provisioningExpiresAt,
      );
      _throwIfCancelled();

      // 4) OS consent.
      _emit(_state.copyWith(phase: ConnectionPhase.preparing));
      final granted = await _vpn.prepare();
      if (!granted) {
        throw const VpnEngineFailure('VPN permission denied.', kind: VpnFailureKind.consentDenied);
      }
      _throwIfCancelled();

      // 5) Hand the decrypted config to the native core.
      _emit(_state.copyWith(phase: ConnectionPhase.starting));
      await _vpn.start(VpnStartRequest(
        sessionId: grant.sessionId,
        singboxConfigJson: profile.singboxConfigJson,
        hardExpiry: profile.expiresAt,
      ));

      // start() returning is not proof the tunnel is up — the native core can
      // fail asynchronously (tun setup, core crash). Confirm before claiming
      // connected; otherwise fail closed.
      await _confirmTunnelUp();

      _emit(_state.copyWith(
        phase: ConnectionPhase.connected,
        expiresAt: profile.expiresAt,
      ));
    } on AppFailure catch (f) {
      await _settleError(f);
    } catch (e) {
      await _settleError(NetworkFailure('Unexpected error.', cause: e));
    }
  }

  /// Wait until the native core reports `connected`, or fail if it reports
  /// `error`/`disconnected` first (or doesn't come up within a short budget).
  Future<void> _confirmTunnelUp() async {
    final current = await _vpn.currentState();
    if (current == VpnConnectionState.connected) return;

    try {
      // Wait only for a terminal SETTLED transition (connected or error). We
      // deliberately ignore `disconnected` here because stateStream replays the
      // current (pre-connect) value, which is `disconnected`; the timeout below
      // bounds the "never comes up" case instead.
      final settled = await _vpn
          .stateStream()
          .firstWhere((s) =>
              s == VpnConnectionState.connected || s == VpnConnectionState.error)
          .timeout(const Duration(seconds: 15));
      if (settled != VpnConnectionState.connected) {
        throw const VpnEngineFailure('Tunnel failed to come up.', kind: VpnFailureKind.startFailed);
      }
    } on TimeoutException {
      throw const VpnEngineFailure('Tunnel did not connect in time.', kind: VpnFailureKind.startFailed);
    }
  }

  /// A user-initiated cancel returns to idle; a real failure surfaces.
  Future<void> _settleError(AppFailure f) async {
    if (_cancelled) {
      await _stopQuietly();
      _emit(ConnectionFlowState.initial);
      return;
    }
    await _failClosed(f);
  }

  /// Graceful teardown. The "watch 1 ad to disconnect" step is intentionally
  /// best-effort and NEVER blocks the actual stop — the tunnel comes down
  /// regardless of whether the closing ad renders.
  Future<void> disconnect({bool showClosingAd = true}) async {
    _signalCancel();
    _emit(_state.copyWith(phase: ConnectionPhase.disconnecting));
    try {
      await _vpn.stop();
    } finally {
      if (showClosingAd) {
        // Fire-and-forget; failures here must not affect disconnect success.
        unawaited(_tryClosingAd());
      }
      _emit(ConnectionFlowState.initial);
    }
  }

  /// Abort an in-flight connect: flips the flag AND cancels the HTTP request so
  /// no bandwidth/work continues in the background.
  void cancel() => _signalCancel();

  void _signalCancel() {
    _cancelled = true;
    final token = _cancelToken;
    if (token != null && !token.isCancelled) token.cancel('user_cancelled');
  }

  // --- internals -------------------------------------------------------------

  /// verify can transiently 409 ('ads not yet verified') if an SSV callback is
  /// still in flight. Retry with backoff until the provisioning window closes.
  Future<VpnProfile> _verifyWithRetry({
    required String grantId,
    required String sessionId,
    required EphemeralSession session,
    required DateTime deadline,
  }) async {
    var attempt = 0;
    while (true) {
      _throwIfCancelled();
      _guardWindow(deadline);
      try {
        return await _repo.verifyAndDecrypt(
          grantId: grantId,
          sessionId: sessionId,
          session: session,
          cancelToken: _cancelToken,
        );
      } on ApiFailure catch (f) {
        final retryable = f.statusCode == 409 &&
            (f.code == 'ads_not_verified' || f.code == null);
        if (!retryable || attempt >= 6) rethrow;
        final backoff = Duration(milliseconds: 400 * (1 << attempt));
        attempt++;
        await Future<void>.delayed(backoff);
        // Re-check after the delay so a cancel/expiry during backoff stops us
        // before firing another request.
        _throwIfCancelled();
        _guardWindow(deadline);
      }
    }
  }

  Future<void> _tryClosingAd() async {
    try {
      // The closing ad has no server-side reward semantics. We pass an explicit
      // sentinel nonce the backend rejects, so even a stray signed SSV callback
      // cannot bind to any live grant.
      await _ads.showRewarded(nonce: closingAdNonce, userId: _userId);
    } catch (_) {/* ignore */}
  }

  Future<void> _stopQuietly() async {
    try {
      await _vpn.stop();
    } catch (_) {/* ignore */}
  }

  Future<void> _failClosed(AppFailure f) async {
    // Make absolutely sure no tunnel is left half-open on any failure path.
    await _stopQuietly();
    _emit(_state.copyWith(phase: ConnectionPhase.failed, failure: f));
  }

  /// Provisioning deadline is enforced authoritatively by the SERVER (verify
  /// returns expired). This client check is a UX fast-fail only, so we allow a
  /// small skew tolerance to avoid rejecting a user whose clock runs slightly
  /// ahead of the server.
  static const Duration _clockSkewGrace = Duration(seconds: 30);

  void _guardWindow(DateTime deadline) {
    if (DateTime.now().toUtc().isAfter(deadline.add(_clockSkewGrace))) {
      throw const ProvisioningExpiredFailure();
    }
  }

  void _throwIfCancelled() {
    if (_cancelled) {
      throw const VpnEngineFailure('Cancelled.', kind: VpnFailureKind.unknown);
    }
  }
}
