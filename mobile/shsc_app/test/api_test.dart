import 'package:flutter_test/flutter_test.dart';
import 'package:shsc_mobile/config.dart';
import 'package:shsc_mobile/core/api/shsc_api.dart';
import 'package:shsc_mobile/core/auth/token_store.dart';

import 'support/fake_backend.dart';

/// API client rules not visible from the UI.
void main() {
  test('concurrent 401s share one rotation of the refresh token', () async {
    final backend = FakeBackend();
    final store = MemoryTokenStore();
    final api = ShscApi(baseUrl: 'http://localhost', store: store, adapter: FakeAdapter(backend));
    await api.login(FakeBackend.email, FakeBackend.password);
    backend.expireAccessTokens();

    final results = await Future.wait([api.overview(), api.devices('h1'), api.unreadCount()]);
    expect(results, hasLength(3));
    expect(backend.requests.where((r) => r.path == '/api/v1/auth/mobile/refresh'), hasLength(1));
    expect(store.refreshToken, 'MOCK-refresh-2');
  });

  test('API errors carry the status and the problem code', () async {
    final backend = FakeBackend()..scanError = 'NO_AUTHORIZED_NETWORK';
    final api = ShscApi(baseUrl: 'http://localhost', store: MemoryTokenStore(), adapter: FakeAdapter(backend));
    await api.login(FakeBackend.email, FakeBackend.password);
    await expectLater(api.requestScan('h1', 'QUICK'),
        throwsA(isA<ApiException>().having((e) => e.status, 'status', 409)
            .having((e) => e.code, 'code', 'NO_AUTHORIZED_NETWORK')));
  });

  test('tokens only over HTTPS, plain HTTP only for local hosts outside release builds', () {
    expect(AppConfig.validateBaseUrl('https://shsc.example/'), 'https://shsc.example');
    expect(AppConfig.validateBaseUrl('http://10.0.2.2:8080'), 'http://10.0.2.2:8080');
    expect(() => AppConfig.validateBaseUrl('http://shsc.example'), throwsArgumentError);
    expect(const AppConfig(apiBaseUrl: 'https://x').pushConfigured, isFalse);
  });
}
