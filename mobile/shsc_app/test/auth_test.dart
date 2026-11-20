import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shsc_mobile/core/auth/token_store.dart';

import 'support/fake_backend.dart';
import 'support/harness.dart';

/// Login, session restore, transparent token rotation, expired session, logout and push
/// registration ([MOCK] backend and push).
void main() {
  testWidgets('wrong credentials show an error; a valid login opens the homes and registers push', (tester) async {
    final backend = FakeBackend();
    final store = MemoryTokenStore();
    final push = FakePushMessaging();
    await pumpApp(tester, backend: backend, store: store, push: push);

    await tester.tap(find.byKey(const Key('sign-in')));
    await tester.pump();
    expect(find.text('Campo obbligatorio'), findsNWidgets(2)); // nothing sent
    expect(backend.called('POST', '/api/v1/auth/mobile/login'), isFalse);

    await signIn(tester, password: 'sbagliata');
    expect(find.text('Email o password non corretti.'), findsOneWidget);
    expect(store.refreshToken, isNull);

    await signIn(tester);
    expect(find.text('Abitazioni'), findsOneWidget);
    expect(find.byKey(const Key('home-h1')), findsOneWidget);
    expect(store.refreshToken, 'MOCK-refresh-1'); // kept in the secure store, never a cookie
    expect(backend.last('POST', '/api/v1/auth/mobile/login').body,
        {'email': FakeBackend.email, 'password': FakeBackend.password, 'deviceLabel': 'SHSC app (ANDROID)'});
    expect(backend.pushRegistrations.values.single,
        {'token': FakePushMessaging.fcmToken, 'platform': 'ANDROID', 'locale': 'it'});
    expect(store.pushRegistration, 'p1');
  });

  testWidgets('a saved session is restored and expired access tokens are rotated transparently', (tester) async {
    final backend = FakeBackend();
    final store = MemoryTokenStore();
    await pumpApp(tester, backend: backend, store: store);
    await signIn(tester);

    // new start of the app with the stored refresh token: no login page
    final restarted = MemoryTokenStore()..refreshToken = store.refreshToken;
    await pumpApp(tester, backend: backend, store: restarted);
    expect(find.byKey(const Key('home-h1')), findsOneWidget);
    expect(restarted.refreshToken, 'MOCK-refresh-2');

    // 15 minutes later: 401, one rotation, the request is repeated
    backend.expireAccessTokens();
    await tester.tap(find.byKey(const Key('home-h1')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('open-devices')));
    await tester.pumpAndSettle();
    expect(find.text('Router MOCK soggiorno'), findsOneWidget); // M20: custom name first
    expect(restarted.refreshToken, 'MOCK-refresh-3');
  });

  testWidgets('a revoked session goes back to the login with a message', (tester) async {
    final backend = FakeBackend();
    final store = MemoryTokenStore();
    await pumpApp(tester, backend: backend, store: store);
    await signIn(tester);

    backend
      ..sessionRevoked = true
      ..expireAccessTokens();
    await tester.tap(find.byKey(const Key('alerts')));
    await tester.pumpAndSettle();
    expect(find.text('La sessione è scaduta: accedi di nuovo.'), findsOneWidget);
    expect(find.byKey(const Key('sign-in')), findsOneWidget);
    expect(store.refreshToken, isNull);
  });

  testWidgets('logout removes the push registration and revokes the session', (tester) async {
    final backend = FakeBackend();
    final store = MemoryTokenStore();
    await pumpApp(tester, backend: backend, store: store, push: FakePushMessaging(), locale: const Locale('en'));
    await signIn(tester);
    expect(find.text('Homes'), findsOneWidget); // English UI

    await tester.tap(find.byKey(const Key('menu')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('logout')));
    await tester.pumpAndSettle();
    expect(backend.called('DELETE', '/api/v1/push-devices/p1'), isTrue);
    expect(backend.last('POST', '/api/v1/auth/mobile/logout').body, {'refreshToken': 'MOCK-refresh-1'});
    expect(backend.pushRegistrations, isEmpty);
    expect(store.refreshToken, isNull);
    expect(find.text('Sign in'), findsWidgets);
  });

  testWidgets('push refused by the user: nothing is registered', (tester) async {
    final backend = FakeBackend();
    await pumpApp(tester, backend: backend, push: FakePushMessaging(granted: false));
    await signIn(tester);
    expect(backend.pushRegistrations, isEmpty);
  });
}
