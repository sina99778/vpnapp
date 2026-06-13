import Foundation
import Security

/// Secure hand-off of the decrypted sing-box config from the main app to the
/// Network Extension. The two run in SEPARATE processes, so we cannot pass the
/// config in memory. We use a **shared Keychain access group** (not an App-Group
/// plist/UserDefaults) because the config carries the VLESS credential — it must
/// be stored encrypted at rest and wiped the moment the session ends.
///
/// Both targets must declare the same Keychain Sharing access group
/// (e.g. "$(AppIdentifierPrefix)app.securevpn.shared") in their entitlements.
enum SharedKeychain {
    static let accessGroup = "app.securevpn.shared"
    private static let service = "app.securevpn.vpnconfig"

    /// Store the config for a session. Overwrites any prior value.
    @discardableResult
    static func putConfig(_ json: String, sessionId: String) -> Bool {
        guard let data = json.data(using: .utf8) else { return false }
        // Delete-then-add keeps it idempotent and avoids SecItemUpdate edge cases.
        deleteConfig(sessionId: sessionId)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: sessionId,
            kSecAttrAccessGroup as String: accessGroup,
            // Available to the extension after first unlock; never leaves device.
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: data,
        ]
        return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
    }

    /// Read the config inside the extension.
    static func readConfig(sessionId: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: sessionId,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess,
              let data = out as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Wipe the config — call on stop/expiry so a credential never lingers.
    static func deleteConfig(sessionId: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: sessionId,
            kSecAttrAccessGroup as String: accessGroup,
        ]
        SecItemDelete(query as CFDictionary)
    }
}
