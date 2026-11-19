import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Where the app keeps the refresh token (docs/06: Keychain/Keystore) and the id of its push
/// registration. The short-lived access token is only kept in memory.
abstract class TokenStore {
  Future<String?> readRefreshToken();
  Future<void> writeRefreshToken(String token);
  Future<String?> readPushRegistration();
  Future<void> writePushRegistration(String? id);
  Future<void> clear();
}

/// Android Keystore / iOS Keychain ("this device only": never restored on another device).
class SecureTokenStore implements TokenStore {
  SecureTokenStore([FlutterSecureStorage? storage])
      : _storage = storage ??
            const FlutterSecureStorage(
              iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock_this_device),
            );

  static const _refresh = 'shsc.refresh_token';
  static const _push = 'shsc.push_registration';
  final FlutterSecureStorage _storage;

  @override
  Future<String?> readRefreshToken() => _storage.read(key: _refresh);

  @override
  Future<void> writeRefreshToken(String token) => _storage.write(key: _refresh, value: token);

  @override
  Future<String?> readPushRegistration() => _storage.read(key: _push);

  @override
  Future<void> writePushRegistration(String? id) =>
      id == null ? _storage.delete(key: _push) : _storage.write(key: _push, value: id);

  @override
  Future<void> clear() async {
    await _storage.delete(key: _refresh);
    await _storage.delete(key: _push);
  }
}

/// Tests and previews.
class MemoryTokenStore implements TokenStore {
  String? refreshToken;
  String? pushRegistration;

  @override
  Future<String?> readRefreshToken() async => refreshToken;

  @override
  Future<void> writeRefreshToken(String token) async => refreshToken = token;

  @override
  Future<String?> readPushRegistration() async => pushRegistration;

  @override
  Future<void> writePushRegistration(String? id) async => pushRegistration = id;

  @override
  Future<void> clear() async {
    refreshToken = null;
    pushRegistration = null;
  }
}
