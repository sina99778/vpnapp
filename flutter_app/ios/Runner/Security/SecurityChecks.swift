import Flutter
import Foundation

/// Pillar 2 (iOS): Swift front for the native C anti-tamper checks (tamper.c).
/// The C layer abort()s on hard signals, so a compromised environment usually
/// terminates the process before returning here.
///
/// Requires the bridging header to expose tamper.h:
///   #import "Security/tamper.h"   // in Runner-Bridging-Header.h
enum SecurityChecks {
    /// Run at app launch, as early as possible.
    static func assertAtStartup() {
        secvpn_anti_debug()
        _ = secvpn_environment_is_tampered() // abort()s inside on detection
    }

    /// Handle the Flutter `assertIntegrity` method.
    static func handle(_ result: @escaping FlutterResult) {
        // Returns 0 (clean) or has already aborted on a hard signal.
        let tampered = secvpn_environment_is_tampered()
        result(tampered == 0)
    }
}
