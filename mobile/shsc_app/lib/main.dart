import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'app.dart';
import 'config.dart';
import 'core/providers.dart';
import 'core/push/push_messaging.dart';

/// Smart Home Security Check, mobile app (Milestone 14, docs/23-MOBILE-APP.md).
///
/// flutter run --dart-define=SHSC_API_BASE_URL=https://shsc.example
///   [--dart-define=SHSC_FIREBASE_API_KEY=... SHSC_FIREBASE_APP_ID=... SHSC_FIREBASE_SENDER_ID=...
///    SHSC_FIREBASE_PROJECT_ID=...]   (push; without them the app works without notifications)
Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final config = AppConfig.fromEnvironment();
  final push = await FirebasePushMessaging.create(config);
  runApp(ProviderScope(
    // no automatic retry of failed requests: errors are shown with a "Retry" button
    retry: (_, _) => null,
    overrides: [
      appConfigProvider.overrideWithValue(config),
      pushMessagingProvider.overrideWithValue(push),
    ],
    child: const ShscApp(),
  ));
}
