/// Connection lifecycle. Native may emit these out of linear order (e.g. a
/// network switch can produce `reconnecting` mid-session), so consumers must
/// treat this as a state machine, not a sequence.
enum VpnConnectionState {
  disconnected,
  connecting,
  connected,
  disconnecting,
  reconnecting,
  error,
}

/// Point-in-time traffic counters streamed from the native core. Cumulative
/// byte totals plus instantaneous speeds.
class TrafficStats {
  const TrafficStats({
    required this.uploadBytes,
    required this.downloadBytes,
    required this.uploadSpeed,
    required this.downloadSpeed,
  });

  final int uploadBytes;
  final int downloadBytes;
  final int uploadSpeed; // bytes/sec
  final int downloadSpeed; // bytes/sec

  static const zero = TrafficStats(
    uploadBytes: 0,
    downloadBytes: 0,
    uploadSpeed: 0,
    downloadSpeed: 0,
  );

  factory TrafficStats.fromMap(Map<dynamic, dynamic> m) => TrafficStats(
        uploadBytes: (m['uploadBytes'] as num?)?.toInt() ?? 0,
        downloadBytes: (m['downloadBytes'] as num?)?.toInt() ?? 0,
        uploadSpeed: (m['uploadSpeed'] as num?)?.toInt() ?? 0,
        downloadSpeed: (m['downloadSpeed'] as num?)?.toInt() ?? 0,
      );
}

/// A connection request handed to the native core. The config is the decrypted
/// sing-box JSON; [hardExpiry] lets the native side self-terminate at the exact
/// server deadline even if the panel is slow to drop the credential.
class VpnStartRequest {
  const VpnStartRequest({
    required this.sessionId,
    required this.singboxConfigJson,
    required this.hardExpiry,
  });

  final String sessionId;
  final String singboxConfigJson;
  final DateTime hardExpiry;
}

/// Abstraction over the native VPN core (sing-box behind Android VpnService /
/// iOS NEPacketTunnelProvider). Dart never parses packets — it only commands
/// the core and observes its state.
abstract interface class VpnEngineService {
  /// Ensure OS-level VPN consent (Android shows a system dialog; iOS loads the
  /// tunnel manager). Returns true if granted. Must be called before [start].
  Future<bool> prepare();

  /// Start the tunnel with a decrypted config. Throws [VpnEngineFailure].
  Future<void> start(VpnStartRequest request);

  /// Stop the tunnel. Idempotent.
  Future<void> stop();

  /// One-shot current state (e.g. on app resume).
  Future<VpnConnectionState> currentState();

  /// Hot stream of state changes. Replays the latest value to new listeners.
  Stream<VpnConnectionState> stateStream();

  /// Hot stream of traffic stats (already throttled on the native side).
  Stream<TrafficStats> trafficStream();
}
