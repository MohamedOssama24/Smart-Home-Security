import 'dart:async';
import 'dart:io' show Platform;

import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';

import '../../config.dart';

/// A notification the user tapped, or one received while the app is open. Only identifiers are
/// carried (alert, home, type): the text is read from the API like the dashboard does.
class PushMessage {
  const PushMessage({this.alertId, this.homeId, this.type, this.title});

  final String? alertId;
  final String? homeId;
  final String? type;
  final String? title;
}

/// Push transport. [FirebasePushMessaging] in the app; a fake in tests; [DisabledPushMessaging]
/// when the build has no Firebase configuration (the app works without push).
abstract class PushMessaging {
  bool get available;
  String get platform;

  /// Asks the OS permission (Android 13+, iOS); false if the user refuses.
  Future<bool> requestPermission();
  Future<String?> token();
  Stream<String> get tokenRefreshed;
  Stream<PushMessage> get foreground;
  Stream<PushMessage> get opened;

  /// The notification that launched the app from terminated state, if any.
  Future<PushMessage?> initialMessage();
}

class DisabledPushMessaging implements PushMessaging {
  @override
  bool get available => false;
  @override
  String get platform => 'ANDROID';
  @override
  Future<bool> requestPermission() async => false;
  @override
  Future<String?> token() async => null;
  @override
  Stream<String> get tokenRefreshed => const Stream.empty();
  @override
  Stream<PushMessage> get foreground => const Stream.empty();
  @override
  Stream<PushMessage> get opened => const Stream.empty();
  @override
  Future<PushMessage?> initialMessage() async => null;
}

class FirebasePushMessaging implements PushMessaging {
  FirebasePushMessaging._();

  /// Initializes Firebase from the build configuration; null if not configured or unavailable.
  static Future<PushMessaging> create(AppConfig config) async {
    if (!config.pushConfigured) {
      return DisabledPushMessaging();
    }
    try {
      await Firebase.initializeApp(
        options: FirebaseOptions(
          apiKey: config.firebaseApiKey,
          appId: config.firebaseAppId,
          messagingSenderId: config.firebaseSenderId,
          projectId: config.firebaseProjectId,
        ),
      );
      return FirebasePushMessaging._();
    } on Exception {
      return DisabledPushMessaging();
    }
  }

  FirebaseMessaging get _fm => FirebaseMessaging.instance;

  @override
  bool get available => true;

  @override
  String get platform => Platform.isIOS ? 'IOS' : 'ANDROID';

  @override
  Future<bool> requestPermission() async {
    final settings = await _fm.requestPermission();
    return settings.authorizationStatus == AuthorizationStatus.authorized ||
        settings.authorizationStatus == AuthorizationStatus.provisional;
  }

  // The FCM registration token is the documented target of the HTTP v1 API used by the backend
  // (message.token). register()/onRegistered return a Firebase Installation ID instead: the
  // migration is left until the server side supports it (docs/23 §7).
  @override
  // ignore: deprecated_member_use
  Future<String?> token() => _fm.getToken();

  @override
  // ignore: deprecated_member_use
  Stream<String> get tokenRefreshed => _fm.onTokenRefresh;

  @override
  Stream<PushMessage> get foreground => FirebaseMessaging.onMessage.map(_map);

  @override
  Stream<PushMessage> get opened => FirebaseMessaging.onMessageOpenedApp.map(_map);

  @override
  Future<PushMessage?> initialMessage() async {
    final m = await _fm.getInitialMessage();
    return m == null ? null : _map(m);
  }

  static PushMessage _map(RemoteMessage m) => PushMessage(
        alertId: m.data['alertId'] as String?,
        homeId: m.data['homeId'] as String?,
        type: m.data['type'] as String?,
        title: m.notification?.title,
      );
}
