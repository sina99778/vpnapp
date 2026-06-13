import 'dart:async';

import 'package:google_mobile_ads/google_mobile_ads.dart';

import '../../../core/config/app_config.dart';
import '../../../core/errors/failures.dart';
import '../domain/ad_reward_service.dart';

/// AdMob implementation of [AdRewardService].
///
/// THE CRITICAL LINE is in [_show]:
///   await ad.setServerSideVerificationOptions(
///     ServerSideVerificationOptions(customData: nonce, userId: userId));
/// This MUST run before `ad.show(...)`. It tells AdMob to echo our single-use
/// `nonce` back to Google's SSV callback as `custom_data`, which our backend
/// matches to the grant. The on-device reward callback is treated as advisory.
class AdMobRewardService implements AdRewardService {
  AdMobRewardService({String? adUnitId})
      : _adUnitId = adUnitId ?? AppConfig.rewardedAdUnitId;

  final String _adUnitId;

  RewardedAd? _ad;
  Completer<void>? _loadCompleter;

  @override
  Future<void> initialize() async {
    await MobileAds.instance.initialize();
  }

  @override
  Future<void> preload() {
    if (_ad != null) return Future<void>.value();
    // Concurrent callers share the ONE in-flight load future — no orphaned
    // Completers that never complete.
    final existing = _loadCompleter;
    if (existing != null) return existing.future;

    final completer = Completer<void>();
    _loadCompleter = completer;

    // RewardedAd.load's own future resolves when the request is *dispatched*;
    // our Completer is driven by the load callbacks below, so we don't await it.
    RewardedAd.load(
      adUnitId: _adUnitId,
      request: const AdRequest(),
      rewardedAdLoadCallback: RewardedAdLoadCallback(
        onAdLoaded: (RewardedAd ad) {
          _ad = ad;
          _loadCompleter = null;
          if (!completer.isCompleted) completer.complete();
        },
        onAdFailedToLoad: (LoadAdError error) {
          _ad = null;
          _loadCompleter = null;
          if (!completer.isCompleted) {
            completer.completeError(
              AdFailure('Ad failed to load.', kind: AdFailureKind.noFill, cause: error),
            );
          }
        },
      ),
    );
    return completer.future;
  }

  @override
  Future<AdPresentation> showRewarded({
    required String nonce,
    required String userId,
  }) async {
    // Ensure an ad is ready; surface load errors as AdFailure.
    if (_ad == null) {
      try {
        await preload();
      } catch (e) {
        if (e is AdFailure) rethrow;
        throw AdFailure('Ad could not be prepared.', cause: e);
      }
    }
    final ad = _ad;
    if (ad == null) {
      throw const AdFailure('No ad available.', kind: AdFailureKind.noFill);
    }

    return _show(ad, nonce: nonce, userId: userId);
  }

  Future<AdPresentation> _show(
    RewardedAd ad, {
    required String nonce,
    required String userId,
  }) async {
    // A RewardedAd is single-use; null our reference now so a concurrent caller
    // can't reuse it, and so we always reload a fresh one next time.
    _ad = null;

    var earnedSignaled = false;
    final done = Completer<AdPresentation>();

    ad.fullScreenContentCallback = FullScreenContentCallback(
      onAdDismissedFullScreenContent: (Ad a) {
        a.dispose();
        if (!done.isCompleted) {
          // Note: onUserEarnedReward (if any) has already fired by here — the
          // SDK guarantees reward-before-dismiss ordering.
          done.complete(AdPresentation(
            completed: true,
            earnedRewardSignaled: earnedSignaled,
          ));
        }
        // Warm the next ad for the second view / next session.
        unawaited(_safePreload());
      },
      onAdFailedToShowFullScreenContent: (Ad a, AdError e) {
        a.dispose();
        if (!done.isCompleted) {
          done.completeError(
            AdFailure('Ad failed to display.', kind: AdFailureKind.showFailed, cause: e),
          );
        }
      },
    );

    try {
      // ── Bind this view to our grant BEFORE showing. ──
      await ad.setServerSideVerificationOptions(
        ServerSideVerificationOptions(customData: nonce, userId: userId),
      );

      await ad.show(
        onUserEarnedReward: (AdWithoutView _, RewardItem __) {
          // Advisory only. We do not grant time here; the backend's SSV
          // callback is the trust anchor.
          earnedSignaled = true;
        },
      );
    } catch (e) {
      ad.dispose();
      if (!done.isCompleted) {
        done.completeError(
          AdFailure('Could not present the ad.', kind: AdFailureKind.showFailed, cause: e),
        );
      }
    }

    // Guard against an SDK that never calls back. Guard isCompleted so a
    // late callback after timeout can't double-complete.
    return done.future.timeout(
      const Duration(minutes: 3),
      onTimeout: () {
        if (!done.isCompleted) {
          done.completeError(const AdFailure('Ad timed out.', kind: AdFailureKind.timeout));
        }
        return done.future;
      },
    );
  }

  Future<void> _safePreload() async {
    try {
      await preload();
    } catch (_) {
      // Best-effort warm-up; the next showRewarded will retry and surface errors.
    }
  }

  @override
  Future<void> dispose() async {
    await _ad?.dispose();
    _ad = null;
    _loadCompleter = null;
  }
}
