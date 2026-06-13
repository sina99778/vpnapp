import Foundation
import NetworkExtension
import Libbox // gomobile-generated module from Libbox.xcframework

/// The iOS tunnel. Runs in its OWN process (the Network Extension), so it cannot
/// be handed the config directly — it reads the decrypted config the app wrote
/// to the shared Keychain, keyed by sessionId (passed in start options).
///
/// libbox drives the flow: `service.start()` calls back into `openTun(_:)`,
/// where we translate libbox's resolved TunOptions into
/// NEPacketTunnelNetworkSettings and return the utun file descriptor.
///
/// NOTE ON BINDINGS: gomobile prefixes symbols with the module name
/// (LibboxNewService, LibboxSetupOptions, LibboxPlatformInterface, ...). Confirm
/// the exact generated signatures against your built Libbox.xcframework; the
/// shapes below match sing-box-for-apple's ExtensionProvider.
class PacketTunnelProvider: NEPacketTunnelProvider, LibboxPlatformInterface {

    private var boxService: LibboxBoxService?
    private var sessionId: String?
    private var expiryTimer: DispatchSourceTimer?

    // MARK: - Tunnel lifecycle

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        guard let sessionId = options?["sessionId"] as? String else {
            completionHandler(TunnelError.missingSession); return
        }
        self.sessionId = sessionId

        // The config (a secret) comes from the shared Keychain, never from the
        // start options or any plaintext App-Group file.
        guard let config = SharedKeychain.readConfig(sessionId: sessionId) else {
            completionHandler(TunnelError.missingConfig); return
        }

        do {
            try Self.setupOnce()
            var newError: NSError?
            // libbox parses config and, during start(), calls openTun(_:) below.
            guard let service = LibboxNewService(config, self, &newError), newError == nil else {
                throw newError ?? TunnelError.coreInit
            }
            try service.start()
            boxService = service

            if let expiry = (options?["hardExpiryEpochMs"] as? NSNumber)?.int64Value, expiry > 0 {
                scheduleHardExpiry(epochMs: expiry)
            }
            completionHandler(nil)
        } catch {
            SharedKeychain.deleteConfig(sessionId: sessionId)
            completionHandler(error)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        expiryTimer?.cancel(); expiryTimer = nil
        try? boxService?.close()
        boxService = nil
        if let sid = sessionId { SharedKeychain.deleteConfig(sessionId: sid) } // wipe the credential
        completionHandler()
    }

    // MARK: - LibboxPlatformInterface

    /// libbox calls this during start(). Translate its resolved options into
    /// NEPacketTunnelNetworkSettings, apply them, and return the utun fd.
    func openTun(_ options: LibboxTunOptions?, _ error: NSErrorPointer) -> Int32 {
        guard let options = options else { error?.pointee = TunnelError.coreInit as NSError; return -1 }
        do {
            let settings = try buildNetworkSettings(from: options)
            // setTunnelNetworkSettings is async; libbox needs a synchronous
            // return, so we block on its completion. This is safe: libbox invokes
            // openTun on its own Go runtime thread (NOT the main thread), and NE
            // delivers the completion on an internal queue — so there is no
            // self-deadlock. (Matches sing-box-for-apple's ExtensionProvider.)
            let sem = DispatchSemaphore(value: 0)
            var applyError: Error?
            setTunnelNetworkSettings(settings) { e in applyError = e; sem.signal() }
            sem.wait()
            if let applyError = applyError { throw applyError }

            // The system created a utun interface; hand its fd to libbox.
            return Self.tunnelFileDescriptor()
        } catch let e {
            error?.pointee = e as NSError
            return -1
        }
    }

    func writeLog(_ message: String?) { /* minimal; never echo config */ }
    func useProcFS() -> Bool { false }
    func underNetworkExtension() -> Bool { true }       // required true inside NE
    func usePlatformAutoDetectInterfaceControl() -> Bool { false } // NE sandbox handles routing
    func autoDetectInterfaceControl(_ fd: Int32) throws { /* no-op on iOS */ }
    func includeAllNetworks() -> Bool { true }

    // MARK: - Helpers

    private func buildNetworkSettings(from options: LibboxTunOptions) throws -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        // iOS NetworkExtension caps tunnel MTU at 4064; clamp so a larger
        // server-configured MTU doesn't cause silent packet drops.
        settings.mtu = NSNumber(value: min(options.getMTU(), 4064))

        // IPv4 addresses + routes.
        let v4 = NEIPv4Settings(addresses: collect(options.getInet4Address()).map(\.address),
                                subnetMasks: collect(options.getInet4Address()).map { prefixToMask($0.prefix) })
        if options.getAutoRoute() { v4.includedRoutes = [NEIPv4Route.default()] }
        settings.ipv4Settings = v4

        // IPv6 (optional).
        let v6addrs = collect(options.getInet6Address())
        if !v6addrs.isEmpty {
            let v6 = NEIPv6Settings(addresses: v6addrs.map(\.address),
                                    networkPrefixLengths: v6addrs.map { NSNumber(value: $0.prefix) })
            if options.getAutoRoute() { v6.includedRoutes = [NEIPv6Route.default()] }
            settings.ipv6Settings = v6
        }

        // DNS. (Confirm StringBox accessor against the generated xcframework.)
        if let dns = try? options.getDNSServerAddress() {
            settings.dnsSettings = NEDNSSettings(servers: [dns.value])
        }
        return settings
    }

    /// Drain a gomobile RoutePrefixIterator into Swift values (Go slices can't
    /// cross the bridge directly).
    private func collect(_ it: LibboxRoutePrefixIterator?) -> [(address: String, prefix: Int32)] {
        var out: [(String, Int32)] = []
        while let it = it, it.hasNext() {
            let p = it.next()
            out.append((p?.address ?? "", p?.prefix ?? 0))
        }
        return out
    }

    private func prefixToMask(_ prefix: Int32) -> String {
        let mask = prefix == 0 ? 0 : (0xFFFF_FFFF << (32 - prefix)) & 0xFFFF_FFFF
        return "\((mask >> 24) & 0xFF).\((mask >> 16) & 0xFF).\((mask >> 8) & 0xFF).\(mask & 0xFF)"
    }

    private func scheduleHardExpiry(epochMs: Int64) {
        let delay = Double(epochMs) / 1000.0 - Date().timeIntervalSince1970
        let timer = DispatchSource.makeTimerSource(queue: .global())
        timer.schedule(deadline: .now() + max(0, delay))
        timer.setEventHandler { [weak self] in
            guard let self = self, self.boxService != nil else { return } // already stopped
            // Wipe the credential SYNCHRONOUSLY at the deadline — do not wait for
            // stopTunnel to run, so the VLESS secret never lingers past expiry.
            if let sid = self.sessionId { SharedKeychain.deleteConfig(sessionId: sid) }
            self.cancelTunnelWithError(nil) // self-terminate at the server deadline
        }
        timer.resume()
        expiryTimer = timer
    }

    private static var didSetup = false
    private static let setupLock = NSLock()
    private static func setupOnce() throws {
        // Libbox.setup must run exactly once per process; guard against a
        // concurrent reconnect racing the first start.
        setupLock.lock()
        defer { setupLock.unlock() }
        guard !didSetup else { return }
        let base = NSHomeDirectory()
        let opts = LibboxSetupOptions()
        opts.basePath = base
        opts.workingPath = base + "/working"
        opts.tempPath = NSTemporaryDirectory()
        var err: NSError?
        LibboxSetup(opts, &err)
        if let err = err { throw err }
        didSetup = true
    }

    /// Locate the utun file descriptor the system created for this extension.
    /// (Standard NE technique: scan fds for the utun control name.)
    private static func tunnelFileDescriptor() -> Int32 {
        var ctlInfo = ctl_info()
        withUnsafeMutablePointer(to: &ctlInfo.ctl_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
                _ = strcpy($0, "com.apple.net.utun_control")
            }
        }
        for fd: Int32 in 0...1024 {
            var addr = sockaddr_ctl()
            var len = socklen_t(MemoryLayout<sockaddr_ctl>.size)
            let result = withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getpeername(fd, $0, &len) }
            }
            if result == 0 && addr.sc_family == AF_SYSTEM { return fd }
        }
        return -1
    }
}

enum TunnelError: Error { case missingSession, missingConfig, coreInit }
