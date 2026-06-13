import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/crypto/payload_crypto.dart';
import '../../../core/network/api_client.dart';
import '../../../core/security/attestation_service.dart';
import '../../../core/storage/secure_store.dart';
import '../../ads/data/admob_reward_service.dart';
import '../../ads/domain/ad_reward_service.dart';
import '../../vpn/data/singbox_vpn_engine.dart';
import '../../vpn/domain/vpn_engine_service.dart';
import '../data/connection_repository.dart';
import '../domain/connection_flow.dart';

// --- singletons (composition root) ------------------------------------------

final secureStoreProvider = Provider<SecureStore>((ref) => SecureStore());

final apiClientProvider = Provider<ApiClient>(
  (ref) => ApiClient(store: ref.watch(secureStoreProvider)),
);

final payloadCryptoProvider = Provider<PayloadCrypto>((ref) => PayloadCrypto());

final attestationServiceProvider = Provider<AttestationService>((ref) => AttestationService());

final adRewardServiceProvider = Provider<AdRewardService>((ref) {
  final svc = AdMobRewardService();
  ref.onDispose(svc.dispose);
  return svc;
});

final vpnEngineProvider = Provider<VpnEngineService>((ref) {
  final engine = SingboxVpnEngine();
  ref.onDispose(engine.dispose);
  return engine;
});

final connectionRepositoryProvider = Provider<ConnectionRepository>(
  (ref) => ConnectionRepository(
    api: ref.watch(apiClientProvider),
    crypto: ref.watch(payloadCryptoProvider),
    attestation: ref.watch(attestationServiceProvider),
  ),
);

/// The signed-in user id, sourced from auth (placeholder here; Phase 1 auth
/// feeds this). Used as AdMob SSV `user_id` and for display.
final currentUserIdProvider = Provider<String>((ref) => 'anonymous');

// --- reactive engine streams ------------------------------------------------

final vpnStateProvider = StreamProvider<VpnConnectionState>(
  (ref) => ref.watch(vpnEngineProvider).stateStream(),
);

final trafficProvider = StreamProvider<TrafficStats>(
  (ref) => ref.watch(vpnEngineProvider).trafficStream(),
);

// --- the flow controller as a StateNotifier ---------------------------------

class ConnectionFlowNotifier extends StateNotifier<ConnectionFlowState> {
  ConnectionFlowNotifier(this._controller) : super(ConnectionFlowState.initial);

  final ConnectionFlowController _controller;

  Future<void> connect() => _controller.connect();
  Future<void> disconnect() => _controller.disconnect();
  void cancel() => _controller.cancel();
}

final connectionFlowProvider =
    StateNotifierProvider<ConnectionFlowNotifier, ConnectionFlowState>((ref) {
  late final ConnectionFlowNotifier notifier;
  final controller = ConnectionFlowController(
    repository: ref.watch(connectionRepositoryProvider),
    ads: ref.watch(adRewardServiceProvider),
    vpn: ref.watch(vpnEngineProvider),
    userId: ref.watch(currentUserIdProvider),
    onState: (s) => notifier.state = s,
  );
  notifier = ConnectionFlowNotifier(controller);
  return notifier;
});
