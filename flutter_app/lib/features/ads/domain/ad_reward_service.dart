import '../../../core/errors/failures.dart';

/// Outcome of presenting a single rewarded ad. Deliberately minimal: it reports
/// only what the CLIENT observed. It does NOT — and must not — assert that the
/// reward is valid. Validity is established exclusively by the backend's SSV
/// callback. The flow controller polls the backend to learn the trusted count.
class AdPresentation {
  const AdPresentation({
    required this.completed,
    required this.earnedRewardSignaled,
  });

  /// The ad was shown and dismissed without a show-time error.
  final bool completed;

  /// AdMob fired onUserEarnedReward on-device. ADVISORY ONLY — a patched client
  /// can forge this; we never grant time based on it.
  final bool earnedRewardSignaled;
}

/// Abstraction over the rewarded-ad network so the connection flow is testable
/// and network-agnostic (AdMob today; AppLovin/Unity could be added later).
abstract interface class AdRewardService {
  /// Initialise the SDK once at app startup.
  Future<void> initialize();

  /// Preload a rewarded ad so [showRewarded] is instant. Safe to call eagerly;
  /// no-op if one is already loaded/loading.
  Future<void> preload();

  /// Show a rewarded ad, injecting [nonce] as AdMob `customData` so the SSV
  /// callback the backend receives is bound to the active grant. [userId] maps
  /// to the SSV `user_id` param (useful for backend correlation/fraud signals).
  ///
  /// Throws [AdFailure] on no-fill, show error, or early dismissal.
  Future<AdPresentation> showRewarded({
    required String nonce,
    required String userId,
  });

  /// Release any held ad resources.
  Future<void> dispose();
}
