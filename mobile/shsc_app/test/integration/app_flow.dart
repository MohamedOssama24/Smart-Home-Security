import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:shsc_mobile/core/auth/token_store.dart';
import 'package:shsc_mobile/core/push/push_messaging.dart';

import '../support/fake_backend.dart';
import '../support/harness.dart';

/// End-to-end flow of the app over real HTTP (dio's socket adapter) against the [MOCK] API served
/// on localhost: login, push registration, dashboard, devices, manual scan followed to the end,
/// alerts opened from a notification, logout. Shared by the VM test (test/integration) and the
/// device test (integration_test/).
Future<void> runAppFlow(WidgetTester tester) async {
  // the widget-test binding replaces HttpClient with a stub answering 400: use real sockets
  HttpOverrides.global = null;
  final backend = FakeBackend();
  final server = await tester.runAsync(() => FakeHttpServer.start(backend));
  addTearDown(() => tester.runAsync(server!.close));
  final store = MemoryTokenStore();
  final push = FakePushMessaging();
  await pumpApp(tester, backend: backend, store: store, push: push, baseUrl: server!.baseUrl, realHttp: true);

  // login
  await pumpUntil(tester, find.byKey(const Key('sign-in')));
  await tester.enterText(find.byKey(const Key('email')), FakeBackend.email);
  await tester.enterText(find.byKey(const Key('password')), FakeBackend.password);
  await tester.tap(find.byKey(const Key('sign-in')));
  await pumpUntil(tester, find.byKey(const Key('home-h1')));
  await pumpUntil(tester, find.byKey(const Key('unread-count')));
  expect(backend.pushRegistrations.values.single['token'], FakePushMessaging.fcmToken);

  // dashboard of the home, devices
  await tester.tap(find.byKey(const Key('home-h1')));
  await pumpUntil(tester, find.text('62/100'));
  await tester.tap(find.byKey(const Key('open-devices')));
  await pumpUntil(tester, find.byKey(const Key('device-d1')));
  await tester.tap(find.byKey(const Key('device-d1')));
  await pumpUntil(tester, find.byKey(const Key('device-category')));
  // the ports are below the identity card (M20): scroll to them
  await tester.scrollUntilVisible(find.byKey(const Key('port-TCP-23')), 200,
      scrollable: find.byType(Scrollable).last);
  await tester.pump(const Duration(seconds: 1)); // end of the page transition, then back
  GoRouter.of(tester.element(find.byType(Scaffold).last)).pop();
  await pumpUntil(tester, find.byKey(const Key('device-d2')));
  await tester.pump(const Duration(seconds: 1)); // end of the page transition, then back
  GoRouter.of(tester.element(find.byType(Scaffold).last)).pop();
  await pumpUntil(tester, find.byKey(const Key('open-scans')));

  // manual scan, followed until completed
  await tester.tap(find.byKey(const Key('open-scans')));
  await pumpUntil(tester, find.byKey(const Key('new-scan')));
  await tester.tap(find.byKey(const Key('new-scan')));
  await pumpUntil(tester, find.byKey(const Key('start-scan')));
  await tester.tap(find.byKey(const Key('start-scan')));
  await pumpUntil(tester, find.text('Completata'));
  expect(backend.last('POST', '/api/v1/homes/h1/scans').body, {'profile': 'STANDARD'});
  expect(find.text('2 dispositivi trovati'), findsOneWidget);

  // a notification is tapped: the alerts open; one is marked read
  push.openedController.add(const PushMessage(alertId: 'a1', homeId: 'h1', type: 'NEW_FINDING'));
  await pumpUntil(tester, find.byKey(const Key('alert-a1')));
  await tester.tap(find.descendant(of: find.byKey(const Key('alert-a1')), matching: find.byKey(const Key('alert-read'))));
  await pumpUntilTrue(tester, () => find.byKey(const Key('alert-read')).evaluate().isEmpty, 'alert a1 read');
  expect(backend.called('POST', '/api/v1/alerts/a1/read'), isTrue);

  // back to the homes and logout: push registration removed, session revoked, tokens forgotten
  GoRouter.of(tester.element(find.byKey(const Key('alert-a1')))).go('/');
  await pumpUntil(tester, find.byKey(const Key('menu')));
  await tester.pump(const Duration(seconds: 1)); // page transition
  await tester.tap(find.byKey(const Key('menu')));
  await pumpUntil(tester, find.byKey(const Key('logout')));
  await tester.pump(const Duration(seconds: 1)); // menu animation
  await tester.tap(find.byKey(const Key('logout')));
  await pumpUntil(tester, find.byKey(const Key('sign-in')));
  expect(backend.pushRegistrations, isEmpty);
  expect(backend.called('POST', '/api/v1/auth/mobile/logout'), isTrue);
  expect(store.refreshToken, isNull);

  // close the app and let the fake clock run out the HTTP timeouts started during the flow
  await tester.pumpWidget(const SizedBox());
  await tester.pump(const Duration(minutes: 1));
}
