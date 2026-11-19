import 'dart:async';

import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shsc_mobile/app.dart';
import 'package:shsc_mobile/config.dart';
import 'package:shsc_mobile/core/auth/token_store.dart';
import 'package:shsc_mobile/core/providers.dart';
import 'package:shsc_mobile/core/push/push_messaging.dart';
import 'package:shsc_mobile/ui/scan_page.dart';

import 'fake_backend.dart';

/// [MOCK] push transport: a fixed token, notifications injected by the test.
class FakePushMessaging implements PushMessaging {
  FakePushMessaging({this.granted = true});

  static const fcmToken = 'MOCK-fcm-token_0123456789abcdefghij';
  final bool granted;
  final openedController = StreamController<PushMessage>.broadcast();
  final foregroundController = StreamController<PushMessage>.broadcast();
  final refreshController = StreamController<String>.broadcast();

  @override
  bool get available => true;
  @override
  String get platform => 'ANDROID';
  @override
  Future<bool> requestPermission() async => granted;
  @override
  Future<String?> token() async => fcmToken;
  @override
  Stream<String> get tokenRefreshed => refreshController.stream;
  @override
  Stream<PushMessage> get foreground => foregroundController.stream;
  @override
  Stream<PushMessage> get opened => openedController.stream;
  @override
  Future<PushMessage?> initialMessage() async => null;
}

/// The whole app (router, localization, providers) on the fake backend.
Future<void> pumpApp(
  WidgetTester tester, {
  required FakeBackend backend,
  TokenStore? store,
  PushMessaging? push,
  String baseUrl = 'http://localhost',
  HttpClientAdapter? adapter,
  bool realHttp = false,
  Locale locale = const Locale('it'),
}) async {
  tester.platformDispatcher.localeTestValue = locale;
  tester.platformDispatcher.localesTestValue = [locale];
  addTearDown(tester.platformDispatcher.clearLocaleTestValue);
  addTearDown(tester.platformDispatcher.clearLocalesTestValue);
  await tester.pumpWidget(const SizedBox()); // a new start: no state kept from a previous app
  await tester.pumpWidget(ProviderScope(
    retry: (_, _) => null,
    overrides: [
      appConfigProvider.overrideWithValue(AppConfig(apiBaseUrl: baseUrl)),
      tokenStoreProvider.overrideWithValue(store ?? MemoryTokenStore()),
      httpAdapterProvider.overrideWithValue(realHttp ? null : adapter ?? FakeAdapter(backend)),
      pushMessagingProvider.overrideWithValue(push ?? DisabledPushMessaging()),
      scanPollIntervalProvider.overrideWithValue(const Duration(milliseconds: 10)),
    ],
    child: const ShscApp(),
  ));
  if (!realHttp) {
    await tester.pumpAndSettle();
  }
}

/// With real sockets the I/O runs outside the fake clock: let it progress, then pump, until
/// [finder] is on screen (or fail after [timeout]).
Future<void> pumpUntil(WidgetTester tester, Finder finder, {Duration timeout = const Duration(seconds: 15)}) =>
    pumpUntilTrue(tester, () => finder.evaluate().isNotEmpty, '$finder', timeout: timeout);

Future<void> pumpUntilTrue(WidgetTester tester, bool Function() done, String what,
    {Duration timeout = const Duration(seconds: 15)}) async {
  final end = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(end)) {
    await tester.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 20)));
    await tester.pump(const Duration(milliseconds: 20));
    if (done()) {
      return;
    }
  }
  fail('Not reached within $timeout: $what');
}

Future<void> signIn(WidgetTester tester, {String password = FakeBackend.password}) async {
  await tester.enterText(find.byKey(const Key('email')), FakeBackend.email);
  await tester.enterText(find.byKey(const Key('password')), password);
  await tester.tap(find.byKey(const Key('sign-in')));
  await tester.pumpAndSettle();
}
