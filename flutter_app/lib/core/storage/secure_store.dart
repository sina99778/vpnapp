import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Thin wrapper over Keychain (iOS) / EncryptedSharedPreferences (Android).
/// Holds the auth + refresh tokens and the device install id. NEVER stores VPN
/// configs or the ephemeral session private key (that stays in memory only).
class SecureStore {
  SecureStore([FlutterSecureStorage? storage])
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(
                encryptedSharedPreferences: true,
                resetOnError: true,
              ),
              iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock),
            );

  final FlutterSecureStorage _storage;

  static const _kAccess = 'auth.access';
  static const _kRefresh = 'auth.refresh';
  static const _kInstallId = 'device.install_id';

  Future<String?> get accessToken => _storage.read(key: _kAccess);
  Future<String?> get refreshToken => _storage.read(key: _kRefresh);
  Future<String?> get installId => _storage.read(key: _kInstallId);

  Future<void> setTokens({required String access, required String refresh}) async {
    await _storage.write(key: _kAccess, value: access);
    await _storage.write(key: _kRefresh, value: refresh);
  }

  Future<void> setAccessToken(String access) => _storage.write(key: _kAccess, value: access);

  Future<void> setInstallId(String id) => _storage.write(key: _kInstallId, value: id);

  Future<void> clearAuth() async {
    await _storage.delete(key: _kAccess);
    await _storage.delete(key: _kRefresh);
  }
}
