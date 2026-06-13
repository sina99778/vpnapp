import Flutter
import NetworkExtension
import UIKit

/// Flutter bridge for the VPN core on iOS. Mirrors the Dart SingboxVpnEngine
/// contract:
///   MethodChannel app.securevpn/vpn         — prepare / start / stop / status
///   EventChannel  app.securevpn/vpn_events  — {type:'state'|'traffic', ...}
///
/// On iOS the tunnel runs in a SEPARATE process (the PacketTunnel extension).
/// The app cannot pass the config in memory, so:
///   • the decrypted config (a secret) is written to the shared Keychain, and
///   • only the sessionId + hard-expiry are passed via the tunnel start options.
/// The extension reads the config from the Keychain in startTunnel.
@main
@objc class AppDelegate: FlutterAppDelegate {

    private let methodChannelName = "app.securevpn/vpn"
    private let eventChannelName = "app.securevpn/vpn_events"
    private let attestChannelName = "app.securevpn/attest"
    private let securityChannelName = "app.securevpn/security"
    private let tunnelBundleId = "app.securevpn.PacketTunnel"

    private var eventSink: FlutterEventSink?
    private var statusObserver: NSObjectProtocol?
    private let attestation = AttestationBridge()

    override func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        // ── Pillar 2: native anti-tamper + anti-debug at the earliest point. ──
        SecurityChecks.assertAtStartup() // abort()s inside on a hard signal

        let controller = window?.rootViewController as! FlutterViewController
        let messenger = controller.binaryMessenger

        FlutterMethodChannel(name: methodChannelName, binaryMessenger: messenger)
            .setMethodCallHandler { [weak self] call, result in
                self?.handle(call, result)
            }

        FlutterEventChannel(name: eventChannelName, binaryMessenger: messenger)
            .setStreamHandler(VpnStreamHandler { [weak self] sink in self?.eventSink = sink })

        // ── Pillar 1: App Attest bridge. ──
        FlutterMethodChannel(name: attestChannelName, binaryMessenger: messenger)
            .setMethodCallHandler { [weak self] call, result in
                guard call.method == "attest",
                      let args = call.arguments as? [String: Any],
                      let hash = args["bindingHash"] as? String else {
                    result(FlutterMethodNotImplemented); return
                }
                self?.attestation.attest(bindingHashB64: hash, result: result)
            }

        FlutterMethodChannel(name: securityChannelName, binaryMessenger: messenger)
            .setMethodCallHandler { call, result in
                guard call.method == "assertIntegrity" else { result(FlutterMethodNotImplemented); return }
                SecurityChecks.handle(result)
            }

        GeneratedPluginRegistrant.register(with: self)
        return super.application(application, didFinishLaunchingWithOptions: launchOptions)
    }

    // MARK: - Method channel

    private func handle(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        switch call.method {
        case "prepare": prepare(result)
        case "start":
            guard let args = call.arguments as? [String: Any],
                  let config = args["config"] as? String,
                  let sessionId = args["sessionId"] as? String else {
                result(FlutterError(code: "bad_config", message: "missing config/sessionId", details: nil))
                return
            }
            let expiry = (args["hardExpiryEpochMs"] as? NSNumber)?.int64Value ?? 0
            start(config: config, sessionId: sessionId, hardExpiryEpochMs: expiry, result: result)
        case "stop": stop(result)
        case "status": loadManager { result($0?.connection.status.bridgeName ?? "disconnected") }
        default: result(FlutterMethodNotImplemented)
        }
    }

    /// "Consent" on iOS = the VPN configuration being installed/enabled. Saving
    /// the manager prompts the user the first time; success ⇒ granted.
    private func prepare(_ result: @escaping FlutterResult) {
        loadOrCreateManager { manager, error in
            guard let manager = manager else {
                result(FlutterError(code: "consent_denied", message: error?.localizedDescription, details: nil))
                return
            }
            manager.isEnabled = true
            manager.saveToPreferences { saveErr in
                result(saveErr == nil)
            }
        }
    }

    private func start(config: String, sessionId: String, hardExpiryEpochMs: Int64, result: @escaping FlutterResult) {
        // 1) Stash the secret config where ONLY the extension can read it.
        guard SharedKeychain.putConfig(config, sessionId: sessionId) else {
            result(FlutterError(code: "bad_config", message: "could not store config", details: nil))
            return
        }
        // 2) Bring up the tunnel; pass non-secret routing info via options.
        loadOrCreateManager { manager, error in
            guard let manager = manager else {
                SharedKeychain.deleteConfig(sessionId: sessionId)
                result(FlutterError(code: "start_failed", message: error?.localizedDescription, details: nil))
                return
            }
            // The manager MUST be saved+reloaded before startVPNTunnel, otherwise
            // iOS rejects the call with "configuration not found / disabled".
            manager.isEnabled = true
            manager.saveToPreferences { saveErr in
                if let saveErr = saveErr {
                    SharedKeychain.deleteConfig(sessionId: sessionId)
                    result(FlutterError(code: "start_failed", message: saveErr.localizedDescription, details: nil))
                    return
                }
                manager.loadFromPreferences { loadErr in
                    guard loadErr == nil,
                          let session = manager.connection as? NETunnelProviderSession else {
                        SharedKeychain.deleteConfig(sessionId: sessionId)
                        result(FlutterError(code: "start_failed", message: loadErr?.localizedDescription, details: nil))
                        return
                    }
                    do {
                        try session.startVPNTunnel(options: [
                            "sessionId": sessionId as NSString,
                            "hardExpiryEpochMs": NSNumber(value: hardExpiryEpochMs),
                        ])
                        result(nil)
                    } catch {
                        SharedKeychain.deleteConfig(sessionId: sessionId)
                        result(FlutterError(code: "start_failed", message: error.localizedDescription, details: nil))
                    }
                }
            }
        }
    }

    private func stop(_ result: @escaping FlutterResult) {
        loadManager { manager in
            manager?.connection.stopVPNTunnel()
            result(nil)
        }
    }

    // MARK: - Manager helpers

    private func loadManager(_ completion: @escaping (NETunnelProviderManager?) -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { managers, _ in
            completion(managers?.first)
        }
    }

    private func loadOrCreateManager(_ completion: @escaping (NETunnelProviderManager?, Error?) -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            if let error = error { completion(nil, error); return }
            let manager = managers?.first ?? NETunnelProviderManager()
            let proto = (manager.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
            proto.providerBundleIdentifier = self?.tunnelBundleId
            // serverAddress is a required display field, not a real address.
            proto.serverAddress = "Secure VPN"
            manager.protocolConfiguration = proto
            manager.localizedDescription = "Secure VPN"
            completion(manager, nil)
        }
    }

    // MARK: - Status stream

    override func applicationDidBecomeActive(_ application: UIApplication) {
        super.applicationDidBecomeActive(application)
        observeStatusIfNeeded()
    }

    private func observeStatusIfNeeded() {
        guard statusObserver == nil else { return }
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: nil, queue: .main
        ) { [weak self] note in
            guard let conn = note.object as? NEVPNConnection else { return }
            self?.eventSink?(["type": "state", "state": conn.status.bridgeName])
            // Traffic is pulled from the extension over IPC; see queryTraffic.
        }
    }
}

/// Maps NEVPNStatus to the EventChannel state names the Dart side expects.
extension NEVPNStatus {
    var bridgeName: String {
        switch self {
        case .connecting: return "connecting"
        case .connected: return "connected"
        case .disconnecting: return "disconnecting"
        case .reasserting: return "reconnecting"
        case .invalid, .disconnected: return "disconnected"
        @unknown default: return "disconnected"
        }
    }
}

/// Minimal EventChannel stream handler.
private class VpnStreamHandler: NSObject, FlutterStreamHandler {
    private let onListen: (@escaping FlutterEventSink) -> Void
    init(_ onListen: @escaping (@escaping FlutterEventSink) -> Void) { self.onListen = onListen }

    func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        onListen(events)
        return nil
    }
    func onCancel(withArguments arguments: Any?) -> FlutterError? { nil }
}
