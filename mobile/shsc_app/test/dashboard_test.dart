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
    expect(find.text('Router MOCK soggiorno'), findsOneWidget); // M20: custom name first
    expect(find.text('Router · 192.168.60.1'), findsOneWidget);
    expect(find.text('Smart TV · 192.168.60.9'), findsOneWidget);

    await tester.tap(find.byKey(const Key('device-d1')));
    await tester.pumpAndSettle();
    expect(find.text('MockNet · Fonti: SSDP'), findsOneWidget);
    expect(find.text('Affidabilità: Alta'), findsOneWidget);
    await tester.scrollUntilVisible(find.byKey(const Key('port-TCP-443')), 200,
        scrollable: find.byType(Scrollable).first); // below the M20 card
    expect(find.byKey(const Key('port-TCP-23')), findsOneWidget);
    expect(find.text('telnet'), findsOneWidget);
    expect(find.text('mock-httpd 1.0'), findsOneWidget);
    // M19: interfaces and IPv4/IPv6 address history (below the services)
    await tester.scrollUntilVisible(find.byKey(const Key('address-fd00:60::211:22ff:fe33:4455')), 200,
        scrollable: find.byType(Scrollable).first);
    expect(find.byKey(const Key('interface-00:11:22:33:44:55')), findsOneWidget);
    expect(find.text('MockNet · eth0'), findsOneWidget);
    expect(find.text('IPv4 · privato · attuale'), findsOneWidget);
    expect(find.text('IPv6 · locale univoco (ULA) · derivato dal MAC (EUI-64) · non più visto'), findsOneWidget);
    // M20: device card with status per field, user confirmation with visible conflict, history
    final scrollable = find.byType(Scrollable).first;
    await tester.scrollUntilVisible(find.byKey(const Key('identity-change-0')), 200, scrollable: scrollable);
    expect(find.text('Firmware: 1.0 → 2.0'), findsOneWidget);
    await tester.scrollUntilVisible(find.byKey(const Key('identity-MANUFACTURER')), -200, scrollable: scrollable);
    expect(find.descendant(of: find.byKey(const Key('identity-status-MANUFACTURER')), matching: find.text('Verificato')),
        findsOneWidget);
    expect(find.text('2.0 · confermato dall\'utente · fonti in disaccordo'), findsOneWidget);
    expect(find.descendant(of: find.byKey(const Key('identity-status-CPE')), matching: find.text('Probabile')),
        findsOneWidget);
    expect(find.descendant(of: find.byKey(const Key('identity-status-PRODUCT_CODE')), matching: find.text('Sconosciuto')),
        findsOneWidget);
    expect(find.text('Router MOCK soggiorno'), findsWidgets); // title and card
    // M24: person associated with the device, read-only
    await tester.scrollUntilVisible(find.byKey(const Key('person-p1')), 200, scrollable: scrollable);
    expect(find.descendant(of: find.byKey(const Key('person-p1')), matching: find.text('Marco')), findsOneWidget);
    expect(find.text('dal nome del dispositivo · Router-di-Marco'), findsOneWidget);
    expect(find.descendant(of: find.byKey(const Key('person-p1')), matching: find.text('Probabile')), findsOneWidget);
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
