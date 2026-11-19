import 'dart:async';

import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../config.dart';
import 'api/models.dart';
import 'api/shsc_api.dart';
import 'auth/token_store.dart';
import 'push/push_messaging.dart';

// --- infrastructure (overridden in main.dart and in the tests) ---------------------------------

final appConfigProvider = Provider<AppConfig>((ref) => AppConfig.fromEnvironment());
final tokenStoreProvider = Provider<TokenStore>((ref) => SecureTokenStore());
final httpAdapterProvider = Provider<HttpClientAdapter?>((ref) => null);
final pushMessagingProvider = Provider<PushMessaging>((ref) => DisabledPushMessaging());

final apiProvider = Provider<ShscApi>((ref) => ShscApi(
      baseUrl: AppConfig.validateBaseUrl(ref.watch(appConfigProvider).apiBaseUrl),
      store: ref.watch(tokenStoreProvider),
      adapter: ref.watch(httpAdapterProvider),
    ));

// --- session ------------------------------------------------------------------------------

sealed class AuthState {
  const AuthState();
}

class AuthRestoring extends AuthState {
  const AuthRestoring();
}

class SignedOut extends AuthState {
  const SignedOut({this.reason});

  /// `expired` (session revoked or expired) or `offline` (server not reachable at start-up).
  final String? reason;
}

class SignedIn extends AuthState {
  const SignedIn(this.me);
  final Me me;
}

final authProvider = NotifierProvider<AuthController, AuthState>(AuthController.new);

/// Session of the app: restored at start-up from the secure storage, then login/logout. After
/// sign-in the installation registers for push (if configured and allowed by the user).
class AuthController extends Notifier<AuthState> {
  StreamSubscription<String>? _tokenRefresh;

  ShscApi get _api => ref.read(apiProvider);

  @override
  AuthState build() {
    ref.read(apiProvider).onSessionExpired = () {
      _stopPush();
      state = const SignedOut(reason: 'expired');
    };
    ref.onDispose(_stopPush);
    Future.microtask(_restore);
    return const AuthRestoring();
  }

  Future<void> _restore() async {
    try {
      if (await _api.restore()) {
        await _signedIn();
      } else {
        state = const SignedOut();
      }
    } on ApiException catch (e) {
      state = SignedOut(reason: e.offline ? 'offline' : null);
    }
  }

  /// Throws [ApiException] (401 wrong credentials, 429 locked, null status offline).
  Future<void> login(String email, String password) async {
    await _api.login(email, password, deviceLabel: 'SHSC app (${ref.read(pushMessagingProvider).platform})');
    await _signedIn();
  }

  Future<void> logout() async {
    _stopPush();
    await _api.unregisterPush();
    await _api.logout();
    state = const SignedOut();
  }

  Future<void> _signedIn() async {
    final me = await _api.me();
    state = SignedIn(me);
    unawaited(_registerPush(me));
  }

  Future<void> _registerPush(Me me) async {
    final push = ref.read(pushMessagingProvider);
    if (!push.available) {
      return;
    }
    try {
      if (!await push.requestPermission()) {
        return;
      }
      final token = await push.token();
      if (token != null) {
        await _api.registerPush(token, push.platform, me.locale);
      }
      _tokenRefresh ??= push.tokenRefreshed.listen((t) => _api.registerPush(t, push.platform, me.locale)
          .then((_) {}, onError: (Object _) {}));
    } on Object {
      // push is optional: the alerts remain in the app and in the dashboard
    }
  }

  void _stopPush() {
    _tokenRefresh?.cancel();
    _tokenRefresh = null;
  }
}

/// Permission check for the UI only: the backend authorizes every request anyway.
final canProvider = Provider.family<bool, String>((ref, permission) {
  final auth = ref.watch(authProvider);
  return auth is SignedIn && auth.me.can(permission);
});

// --- data ---------------------------------------------------------------------------------

final overviewProvider = FutureProvider.autoDispose<List<HomeOverview>>((ref) => ref.watch(apiProvider).overview());

final devicesProvider =
    FutureProvider.autoDispose.family<List<Device>, String>((ref, homeId) => ref.watch(apiProvider).devices(homeId));

final deviceProvider =
    FutureProvider.autoDispose.family<Device, String>((ref, id) => ref.watch(apiProvider).device(id));

final scansProvider =
    FutureProvider.autoDispose.family<List<Scan>, String>((ref, homeId) => ref.watch(apiProvider).scans(homeId));

final alertsProvider = FutureProvider.autoDispose.family<List<AlertItem>, bool>(
    (ref, unreadOnly) => ref.watch(apiProvider).alerts(unreadOnly: unreadOnly));

final unreadCountProvider = FutureProvider.autoDispose<int>((ref) async {
  final auth = ref.watch(authProvider);
  return auth is SignedIn ? ref.watch(apiProvider).unreadCount() : 0;
});
