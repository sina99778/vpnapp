import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'features/ads/domain/ad_reward_service.dart';
import 'features/connection/domain/connection_flow.dart';
import 'features/connection/presentation/connection_providers.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  final container = ProviderContainer();

  // Warm the ads SDK + first rewarded ad so the connect flow is instant.
  final ads = container.read(adRewardServiceProvider);
  await ads.initialize();
  // ignore: unawaited_futures
  ads.preload();

  runApp(UncontrolledProviderScope(container: container, child: const SecureVpnApp()));
}

class SecureVpnApp extends StatelessWidget {
  const SecureVpnApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Secure VPN',
      theme: ThemeData.dark(useMaterial3: true),
      home: const _HomeStub(),
    );
  }
}

/// Minimal stub wiring the flow to a button — full UI is later in Phase 2.
class _HomeStub extends ConsumerWidget {
  const _HomeStub();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final flow = ref.watch(connectionFlowProvider);
    final notifier = ref.read(connectionFlowProvider.notifier);

    return Scaffold(
      body: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(flow.phase.name, style: Theme.of(context).textTheme.headlineSmall),
            if (flow.phase == ConnectionPhase.showingAds)
              Text('Ad ${flow.adsWatched}/${flow.adsRequired}'),
            if (flow.failure != null)
              Padding(
                padding: const EdgeInsets.all(8),
                child: Text(flow.failure!.message, style: const TextStyle(color: Colors.redAccent)),
              ),
            const SizedBox(height: 16),
            FilledButton(
              onPressed: flow.isBusy
                  ? null
                  : (flow.phase == ConnectionPhase.connected
                      ? notifier.disconnect
                      : notifier.connect),
              child: Text(flow.phase == ConnectionPhase.connected ? 'Disconnect' : 'Connect'),
            ),
          ],
        ),
      ),
    );
  }
}
