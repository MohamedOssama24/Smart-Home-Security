import 'package:flutter/foundation.dart';

/// Build-time configuration (`--dart-define`), nothing secret: the API address and the public
/// identifiers of the owner's Firebase project. Without Firebase values push is disabled.
class AppConfig {
  const AppConfig({
    required this.apiBaseUrl,
    this.firebaseApiKey = '',
    this.firebaseAppId = '',
    this.firebaseSenderId = '',
    this.firebaseProjectId = '',
  });

  factory AppConfig.fromEnvironment() => const AppConfig(
        apiBaseUrl: String.fromEnvironment('SHSC_API_BASE_URL', defaultValue: 'https://10.0.2.2'),
        firebaseApiKey: String.fromEnvironment('SHSC_FIREBASE_API_KEY'),
        firebaseAppId: String.fromEnvironment('SHSC_FIREBASE_APP_ID'),
        firebaseSenderId: String.fromEnvironment('SHSC_FIREBASE_SENDER_ID'),
        firebaseProjectId: String.fromEnvironment('SHSC_FIREBASE_PROJECT_ID'),
      );

  final String apiBaseUrl;
  final String firebaseApiKey;
  final String firebaseAppId;
  final String firebaseSenderId;
  final String firebaseProjectId;

  bool get pushConfigured => [firebaseApiKey, firebaseAppId, firebaseSenderId, firebaseProjectId]
      .every((v) => v.isNotEmpty);

  /// Tokens travel only over HTTPS; plain HTTP is accepted only for local hosts in debug builds
  /// (and in tests), never in a release build.
  static String validateBaseUrl(String url) {
    final uri = Uri.parse(url);
    final local = const {'localhost', '127.0.0.1', '10.0.2.2'}.contains(uri.host);
    if (uri.scheme == 'https' || (uri.scheme == 'http' && local && !kReleaseMode)) {
      return url.endsWith('/') ? url.substring(0, url.length - 1) : url;
    }
    throw ArgumentError('SHSC_API_BASE_URL must use HTTPS');
  }
}
