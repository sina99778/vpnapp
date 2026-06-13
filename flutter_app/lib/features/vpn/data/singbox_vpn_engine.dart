import 'dart:async';

import 'package:flutter/services.dart';

import '../../../core/config/app_config.dart';
import '../../../core/errors/failures.dart';
import '../domain/vpn_engine_service.dart';

/// Platform-channel bridge to the native sing-box core.
///
/// Division of responsibility (see Phase 2 notes):
///   • Dart  — commands the core, validates/forwards the config string, exposes
///             reactive streams. It NEVER touches packets or the tun fd.
///   • Native (Kotlin VpnService / Swift NEPacketTunnelProvider) — owns the tun
///             interface, the sing-box runtime, socket protection, the
///             foreground service, and emits state/traffic events.
///
/// Two channels:
///   • MethodChannel  — request/response commands (prepare, start, stop, status).
///   • EventChannel   — native→Dart broadcast of state + throttled traffic.
class SingboxVpnEngine implements VpnEngineService {
  SingboxVpnEngine({
    MethodChannel? method,
    EventChannel? events,
  })  : _method = method ?? const MethodChannel(AppConfig.vpnMethodChannel),
        _events = events ?? const EventChannel(AppConfig.vpnEventChannel) {
    _subscribe();
  }

  final MethodChannel _method;
  final EventChannel _events;

  // Broadcast controllers with last-value replay for late subscribers.
  final _stateController = StreamController<VpnConnectionState>.broadcast();
  final _trafficController = StreamController<TrafficStats>.broadcast();
  VpnConnectionState _lastState = VpnConnectionState.disconnected;
  TrafficStats _lastTraffic = TrafficStats.zero;
  StreamSubscription<dynamic>? _eventSub;

  void _subscribe() {
    _eventSub = _events.receiveBroadcastStream().listen(
      _onNativeEvent,
      onError: (Object e, StackTrace _) {
        _lastState = VpnConnectionState.error;
        if (!_stateController.isClosed) _stateController.add(_lastState);
      },
    );
  }

  void _onNativeEvent(dynamic event) {
    if (event is! Map) return;
    switch (event['type']) {
      case 'state':
        final s = _parseState(event['state'] as String?);
        _lastState = s;
        if (!_stateController.isClosed) _stateController.add(s);
      case 'traffic':
        final t = TrafficStats.fromMap(event);
        _lastTraffic = t;
        if (!_trafficController.isClosed) _trafficController.add(t);
    }
  }

  @override
  Future<bool> prepare() async {
    try {
      // Native returns true if consent already granted or the user grants it;
      // false if the user denies. (Android: VpnService.prepare + Activity
      // result; iOS: NETunnelProviderManager load/save.)
      final granted = await _method.invokeMethod<bool>('prepare');
      return granted ?? false;
    } on PlatformException catch (e) {
      throw VpnEngineFailure(
        'VPN permission could not be requested.',
        kind: VpnFailureKind.consentDenied,
        cause: e,
      );
    }
  }

  @override
  Future<void> start(VpnStartRequest request) async {
    try {
      await _method.invokeMethod<void>('start', <String, dynamic>{
        'sessionId': request.sessionId,
        'config': request.singboxConfigJson,
        'hardExpiryEpochMs': request.hardExpiry.toUtc().millisecondsSinceEpoch,
      });
    } on PlatformException catch (e) {
      throw VpnEngineFailure(
        _startMessageFor(e.code),
        kind: _startKindFor(e.code),
        cause: e,
      );
    }
  }

  @override
  Future<void> stop() async {
    try {
      await _method.invokeMethod<void>('stop');
    } on PlatformException catch (e) {
      // Stop is best-effort; surface but don't crash the UI.
      throw VpnEngineFailure('Failed to stop the VPN.', cause: e);
    }
  }

  @override
  Future<VpnConnectionState> currentState() async {
    try {
      final raw = await _method.invokeMethod<String>('status');
      return _parseState(raw);
    } on PlatformException {
      return _lastState;
    }
  }

  @override
  Stream<VpnConnectionState> stateStream() async* {
    yield _lastState; // replay latest
    yield* _stateController.stream;
  }

  @override
  Stream<TrafficStats> trafficStream() async* {
    yield _lastTraffic;
    yield* _trafficController.stream;
  }

  Future<void> dispose() async {
    await _eventSub?.cancel();
    await _stateController.close();
    await _trafficController.close();
  }

  // --- mapping helpers -------------------------------------------------------

  VpnConnectionState _parseState(String? raw) {
    switch (raw) {
      case 'connecting':
        return VpnConnectionState.connecting;
      case 'connected':
        return VpnConnectionState.connected;
      case 'disconnecting':
        return VpnConnectionState.disconnecting;
      case 'reconnecting':
        return VpnConnectionState.reconnecting;
      case 'error':
        return VpnConnectionState.error;
      case 'disconnected':
      default:
        return VpnConnectionState.disconnected;
    }
  }

  String _startMessageFor(String code) => switch (code) {
        'consent_denied' => 'VPN permission was denied.',
        'already_running' => 'A VPN session is already active.',
        'bad_config' => 'The server configuration was rejected by the core.',
        _ => 'The VPN core failed to start.',
      };

  VpnFailureKind _startKindFor(String code) => switch (code) {
        'consent_denied' => VpnFailureKind.consentDenied,
        'already_running' => VpnFailureKind.alreadyRunning,
        'bad_config' => VpnFailureKind.startFailed,
        _ => VpnFailureKind.startFailed,
      };
}
