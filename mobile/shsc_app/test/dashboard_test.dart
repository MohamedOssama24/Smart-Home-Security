import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fake_backend.dart';
import 'support/harness.dart';

/// Homes, home dashboard, devices and device detail ([MOCK] data).
void main() {
  testWidgets('homes, score and issues, devices and their exposed services', (tester) async {
    final backend = FakeBackend();
    await pumpApp(tester, backend: backend);
    await signIn(tester);

    final card = find.byKey(const Key('home-h1'));
    expect(find.descendant(of: card, matching: find.text('Casa MOCK')), findsOneWidget);
    expect(find.descendant(of: card, matching: find.text('62')), findsOneWidget);
    expect(find.descendant(of: card, matching: find.text('Rischio alto')), findsOneWidget);
    expect(find.descendant(of: card, matching: find.text('3 problemi aperti')), findsOneWidget);
    expect(find.descendant(of: card, matching: find.text('2 dispositivi')), findsOneWidget);

    await tester.tap(card);
    await tester.pumpAndSettle();
    expect(find.text('62/100'), findsOneWidget);
    expect(find.text('-15 punti dall\'ultima volta'), findsOneWidget);
    expect(find.text('Alta: 1'), findsOneWidget);
    expect(find.text('Media: 2'), findsOneWidget);
    expect(find.text('1 vulnerabilità sfruttata attivamente'), findsOneWidget);

    await tester.tap(find.byKey(const Key('open-devices')));
    await tester.pumpAndSettle();
    expect(find.text('mock-router'), findsOneWidget);
    expect(find.text('Router · 192.168.60.1'), findsOneWidget);
    expect(find.text('Smart TV · 192.168.60.9'), findsOneWidget);

    await tester.tap(find.byKey(const Key('device-d1')));
    await tester.pumpAndSettle();
    expect(find.text('MockNet'), findsOneWidget);
    expect(find.text('Affidabilità: Alta'), findsOneWidget);
    expect(find.byKey(const Key('port-TCP-23')), findsOneWidget);
    expect(find.text('telnet'), findsOneWidget);
    expect(find.text('mock-httpd 1.0'), findsOneWidget);
  });

  testWidgets('without finding:read and scan:read the security data and scans are hidden', (tester) async {
    final backend = FakeBackend(permissions: {'home:read', 'device:read'});
    await pumpApp(tester, backend: backend);
    await signIn(tester);
    expect(find.text('Il tuo ruolo non permette di vedere i dati di sicurezza.'), findsOneWidget);
    await tester.tap(find.byKey(const Key('home-h1')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('open-devices')), findsOneWidget);
    expect(find.byKey(const Key('open-scans')), findsNothing);
  });

  testWidgets('server unreachable: error with retry', (tester) async {
    final backend = FakeBackend();
    await pumpApp(tester, backend: backend, adapter: _OfflineAfterLogin(backend));
    await signIn(tester);
    expect(find.text('Impossibile contattare il server. Controlla la connessione.'), findsOneWidget);
    expect(find.text('Riprova'), findsOneWidget);
  });
}

/// Logs in, then every data request fails as without network.
class _OfflineAfterLogin extends FakeAdapter {
  _OfflineAfterLogin(super.backend);

  @override
  Future<ResponseBody> fetch(RequestOptions options, Stream<Uint8List>? requestStream, Future<void>? cancelFuture) {
    if (options.uri.path.endsWith('/overview')) {
      throw DioException.connectionError(requestOptions: options, reason: 'MOCK offline');
    }
    return super.fetch(options, requestStream, cancelFuture);
  }
}
