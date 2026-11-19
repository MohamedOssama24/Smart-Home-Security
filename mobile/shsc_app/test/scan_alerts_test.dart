import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shsc_mobile/core/push/push_messaging.dart';

import 'support/fake_backend.dart';
import 'support/harness.dart';

/// Manual scan request and follow-up, alerts and push notifications ([MOCK] backend: nothing is
/// scanned).
void main() {
  Future<void> openScans(WidgetTester tester) async {
    await tester.tap(find.byKey(const Key('home-h1')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('open-scans')));
    await tester.pumpAndSettle();
  }

  testWidgets('starts a manual scan after confirmation and follows it until completed', (tester) async {
    final backend = FakeBackend();
    await pumpApp(tester, backend: backend);
    await signIn(tester);
    await openScans(tester);
    expect(find.text('Standard · Completata'), findsOneWidget);

    await tester.tap(find.byKey(const Key('new-scan')));
    await tester.pumpAndSettle();
    expect(find.textContaining('solo sulle reti che hai autorizzato'), findsOneWidget);
    await tester.tap(find.byKey(const Key('profile-QUICK')));
    await tester.pumpAndSettle();
    expect(find.text('Dispositivi e porte più comuni: pochi minuti.'), findsOneWidget);
    await tester.tap(find.byKey(const Key('start-scan')));
    await tester.pumpAndSettle();

    final post = backend.last('POST', '/api/v1/homes/h1/scans');
    expect(post.body, {'profile': 'QUICK'});
    expect(post.headers['idempotency-key'], matches(RegExp(r'^[A-Za-z0-9_-]{8,64}$')));
    // polled until the end: QUEUED -> RUNNING -> COMPLETED
    expect(find.byKey(const Key('scan-status')), findsOneWidget);
    expect(find.text('Completata'), findsOneWidget);
    expect(find.text('2 dispositivi trovati'), findsOneWidget);
    expect(backend.requests.where((r) => r.path == '/api/v1/scans/s2').length, 3);
    expect(find.byKey(const Key('scan-open-devices')), findsOneWidget);
  });

  testWidgets('a refused request shows the reason; without scan:create there is no button', (tester) async {
    final backend = FakeBackend()..scanError = 'AGENT_OFFLINE';
    await pumpApp(tester, backend: backend);
    await signIn(tester);
    await openScans(tester);
    await tester.tap(find.byKey(const Key('new-scan')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('start-scan')));
    await tester.pumpAndSettle();
    expect(find.text('L\'agent dell\'abitazione non è raggiungibile.'), findsOneWidget);

    final readOnly = FakeBackend(permissions: {'home:read', 'finding:read', 'scan:read'});
    await pumpApp(tester, backend: readOnly);
    await signIn(tester);
    await openScans(tester);
    expect(find.byKey(const Key('new-scan')), findsNothing);
  });

  testWidgets('alerts: texts from the payload, unread counter, mark as read; a tapped push opens them',
      (tester) async {
    final backend = FakeBackend();
    final push = FakePushMessaging();
    await pumpApp(tester, backend: backend, push: push);
    await signIn(tester);
    expect(find.byKey(const Key('unread-count')), findsOneWidget);
    expect(find.text('1'), findsWidgets);

    // the user taps a notification: the app opens the alerts
    push.openedController.add(const PushMessage(alertId: 'a1', homeId: 'h1', type: 'NEW_FINDING'));
    await tester.pumpAndSettle();
    expect(find.text('Avvisi'), findsWidgets);
    final titles = tester.widgetList<Text>(find.byKey(const Key('alert-title'))).map((t) => t.data).toList();
    expect(titles, ['Nuovo problema di sicurezza', 'Il punteggio è sceso']);
    final first = find.byKey(const Key('alert-a1'));
    expect(find.descendant(of: first, matching: find.text('Alta · mock-router (192.168.60.1)')), findsOneWidget);
    expect(find.descendant(of: first, matching: find.text('Ripetuto 3 volte')), findsOneWidget);
    expect(find.text('Ora 58/100 (-15 punti)'), findsOneWidget);

    await tester.tap(find.descendant(of: first, matching: find.byKey(const Key('alert-read'))));
    await tester.pumpAndSettle();
    expect(backend.called('POST', '/api/v1/alerts/a1/read'), isTrue);
    expect(find.byKey(const Key('alert-read')), findsNothing);
    expect(backend.alerts.where((a) => a['readAt'] == null), isEmpty);
  });
}
