import 'dart:async';
import 'dart:math';

import 'package:dio/dio.dart';

import '../auth/token_store.dart';
import 'models.dart';

/// Error of an API call: HTTP status and the RFC 9457 `code` when the backend sent one.
class ApiException implements Exception {
  ApiException(this.status, this.code, [this.detail]);

  final int? status;
  final String? code;
  final String? detail;

  bool get offline => status == null;

  @override
  String toString() => 'ApiException($status, $code)';
}

/// Client of the existing REST API (`/api/v1`) with the mobile authentication of the backend
/// (`/auth/mobile/*`, docs/23-MOBILE-APP.md §2):
/// - the access token stays in memory and is sent as Bearer;
/// - on a 401 the refresh token (secure storage) is rotated once and the request retried;
///   concurrent 401s share the same refresh;
/// - if the refresh fails the session is over and [onSessionExpired] is called.
class ShscApi {
  ShscApi({required String baseUrl, required this._store, HttpClientAdapter? adapter})
      : _dio = Dio(_options(baseUrl)),
        _auth = Dio(_options(baseUrl)) {
    if (adapter != null) {
      _dio.httpClientAdapter = adapter;
      _auth.httpClientAdapter = adapter;
    }
    _dio.interceptors.add(InterceptorsWrapper(onRequest: _onRequest, onError: _onError));
  }

  static BaseOptions _options(String baseUrl) => BaseOptions(
        baseUrl: baseUrl,
        connectTimeout: const Duration(seconds: 15),
        receiveTimeout: const Duration(seconds: 30),
        headers: {'Accept': 'application/json'},
        followRedirects: false,
      );

  final TokenStore _store;
  final Dio _dio;
  final Dio _auth;
  String? _accessToken;
  Future<bool>? _refreshing;

  /// Called when the session cannot be renewed (revoked, expired, token reused).
  void Function()? onSessionExpired;

  bool get hasSession => _accessToken != null;

  // --- authentication -----------------------------------------------------------------------

  Future<void> login(String email, String password, {String deviceLabel = 'SHSC app'}) async {
    final res = await _call(() => _auth.post<Map<String, dynamic>>('/api/v1/auth/mobile/login',
        data: {'email': email.trim(), 'password': password, 'deviceLabel': deviceLabel}));
    await _accept(res.data!);
  }

  /// Resumes the session saved on the device; false if there is none or it is no longer valid.
  Future<bool> restore() async {
    if (await _store.readRefreshToken() == null) {
      return false;
    }
    return _refresh();
  }

  /// Revokes the session on the server (best effort) and forgets the tokens.
  Future<void> logout() async {
    final refresh = await _store.readRefreshToken();
    if (refresh != null) {
      try {
        await _auth.post<void>('/api/v1/auth/mobile/logout', data: {'refreshToken': refresh});
      } on DioException {
        // offline: the local session is cleared anyway; the server session expires by itself
      }
    }
    _accessToken = null;
    await _store.clear();
  }

  Future<void> _accept(Map<String, dynamic> body) async {
    _accessToken = body['accessToken'] as String;
    await _store.writeRefreshToken(body['refreshToken'] as String);
  }

  Future<bool> _refresh() {
    return _refreshing ??= () async {
      try {
        final refresh = await _store.readRefreshToken();
        if (refresh == null) {
          return false;
        }
        final res = await _auth.post<Map<String, dynamic>>('/api/v1/auth/mobile/refresh',
            data: {'refreshToken': refresh});
        await _accept(res.data!);
        return true;
      } on DioException catch (e) {
        if (e.response?.statusCode == 401 || e.response?.statusCode == 400) {
          _accessToken = null;
          await _store.clear();
          return false;
        }
        throw _map(e); // offline: keep the stored session for later
      } finally {
        _refreshing = null;
      }
    }();
  }

  void _onRequest(RequestOptions options, RequestInterceptorHandler handler) {
    if (_accessToken != null) {
      options.headers['Authorization'] = 'Bearer $_accessToken';
    }
    handler.next(options);
  }

  Future<void> _onError(DioException error, ErrorInterceptorHandler handler) async {
    final options = error.requestOptions;
    if (error.response?.statusCode != 401 || options.extra['retried'] == true) {
      return handler.next(error);
    }
    bool renewed;
    try {
      renewed = await _refresh();
    } on ApiException {
      return handler.next(error);
    }
    if (!renewed) {
      onSessionExpired?.call();
      return handler.next(error);
    }
    options.extra['retried'] = true;
    options.headers['Authorization'] = 'Bearer $_accessToken';
    try {
      handler.resolve(await _dio.fetch<dynamic>(options));
    } on DioException catch (e) {
      handler.next(e);
    }
  }

  // --- data ---------------------------------------------------------------------------------

  Future<Me> me() async => Me.fromJson(await _get('/api/v1/me'));

  Future<List<HomeOverview>> overview() async =>
      (await _list('/api/v1/overview')).map(HomeOverview.fromJson).toList();

  Future<List<Device>> devices(String homeId) async =>
      (await _list('/api/v1/homes/${_seg(homeId)}/devices')).map(Device.fromJson).toList();

  /// People of the home with their devices (M24), one entry per (person, device).
  Future<List<DevicePerson>> devicePeople(String homeId) async =>
      DevicePerson.fromPeople(await _list('/api/v1/homes/${_seg(homeId)}/people'));

  Future<Device> device(String deviceId) async => Device.fromJson(await _get('/api/v1/devices/${_seg(deviceId)}'));

  Future<List<Scan>> scans(String homeId) async =>
      (await _list('/api/v1/homes/${_seg(homeId)}/scans')).map(Scan.fromJson).toList();

  Future<Scan> scan(String scanId) async => Scan.fromJson(await _get('/api/v1/scans/${_seg(scanId)}'));

  /// Manual scan of the home's authorized networks through its agent (the backend checks
  /// permissions, authorization and the agent; nothing is scanned by the phone).
  Future<Scan> requestScan(String homeId, String profile, {String? idempotencyKey}) async {
    final res = await _call(() => _dio.post<Map<String, dynamic>>('/api/v1/homes/${_seg(homeId)}/scans',
        data: {'profile': profile},
        options: Options(headers: {'Idempotency-Key': idempotencyKey ?? newIdempotencyKey()})));
    return Scan.fromJson(res.data!);
  }

  Future<Scan> cancelScan(String scanId) async {
    final res = await _call(() => _dio.post<Map<String, dynamic>>('/api/v1/scans/${_seg(scanId)}/cancel', data: {}));
    return Scan.fromJson(res.data!);
  }

  Future<List<AlertItem>> alerts({bool unreadOnly = false, int limit = 100}) async =>
      (await _list('/api/v1/alerts?unread=$unreadOnly&limit=$limit')).map(AlertItem.fromJson).toList();

  Future<int> unreadCount() async => ((await _get('/api/v1/alerts/unread-count'))['count'] as num?)?.toInt() ?? 0;

  Future<void> markRead(String alertId) =>
      _call(() => _dio.post<void>('/api/v1/alerts/${_seg(alertId)}/read'));

  Future<void> markAllRead() => _call(() => _dio.post<void>('/api/v1/alerts/read-all'));

  /// Registers this installation for push; returns the registration id.
  Future<String> registerPush(String token, String platform, String locale) async {
    final res = await _call(() => _dio.post<Map<String, dynamic>>('/api/v1/push-devices',
        data: {'token': token, 'platform': platform, 'locale': locale}));
    final id = res.data!['id'] as String;
    await _store.writePushRegistration(id);
    return id;
  }

  /// Removes this installation's push registration (before logout).
  Future<void> unregisterPush() async {
    final id = await _store.readPushRegistration();
    if (id == null) {
      return;
    }
    try {
      await _call(() => _dio.delete<void>('/api/v1/push-devices/${_seg(id)}'));
    } on ApiException {
      // already removed, or offline: the logout stops the pushes anyway
    }
    await _store.writePushRegistration(null);
  }

  // --- helpers ------------------------------------------------------------------------------

  static String newIdempotencyKey() {
    final r = Random.secure();
    return List.generate(16, (_) => r.nextInt(256).toRadixString(16).padLeft(2, '0')).join();
  }

  static String _seg(String id) => Uri.encodeComponent(id);

  Future<Map<String, dynamic>> _get(String path) async {
    final res = await _call(() => _dio.get<Map<String, dynamic>>(path));
    return res.data!;
  }

  Future<List<Map<String, dynamic>>> _list(String path) async {
    final res = await _call(() => _dio.get<List<dynamic>>(path));
    return res.data!.map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  Future<Response<T>> _call<T>(Future<Response<T>> Function() request) async {
    try {
      return await request();
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  static ApiException _map(DioException e) {
    final data = e.response?.data;
    final problem = data is Map ? data : const {};
    return ApiException(e.response?.statusCode, problem['code'] as String?, problem['detail'] as String?);
  }
}
