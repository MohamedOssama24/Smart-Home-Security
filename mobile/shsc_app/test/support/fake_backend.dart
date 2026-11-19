import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dio/dio.dart';

/// [MOCK] In-memory imitation of the SHSC REST API used by the app (same paths, payloads and error
/// codes as the real backend, docs/05 and docs/23). Fictitious home, devices and tokens only.
class FakeBackend {
  FakeBackend({Set<String>? permissions})
      : permissions = permissions ??
            {'home:read', 'finding:read', 'device:read', 'scan:read', 'scan:create'};

  static const email = 'owner-mock@example.test';
  static const password = 'MOCK-password-42';

  final Set<String> permissions;
  final requests = <RecordedRequest>[];
  final pushRegistrations = <String, Map<String, dynamic>>{};

  /// Valid access tokens and refresh tokens (consumed ones detect reuse).
  final _access = <String>{};
  final _refresh = <String>{};
  final _consumed = <String>{};
  int _seq = 0;
  bool sessionRevoked = false;
  String? scanError;

  final List<Map<String, dynamic>> scans = [
    _scan('s1', 'COMPLETED', devices: 2, completedAt: '2026-11-18T09:10:00Z'),
  ];
  final Map<String, int> _scanPolls = {};

  final List<Map<String, dynamic>> alerts = [
    {
      'id': 'a1', 'homeId': 'h1', 'homeName': 'Casa MOCK', 'deviceId': 'd1', 'type': 'NEW_FINDING',
      'severity': 'HIGH', 'occurrences': 3, 'firstAt': '2026-11-18T09:00:00Z', 'lastAt': '2026-11-18T10:00:00Z',
      'resolvedAt': null, 'readAt': null,
      'payload': {'findingSeverity': 'HIGH', 'deviceName': 'mock-router', 'deviceIp': '192.168.60.1',
          'titleKey': 'findings.rule.telnet-open.title', 'params': {'port': 23}},
    },
    {
      'id': 'a2', 'homeId': 'h1', 'homeName': 'Casa MOCK', 'deviceId': null, 'type': 'SCORE_DROPPED',
      'severity': 'MEDIUM', 'occurrences': 1, 'firstAt': '2026-11-18T08:00:00Z', 'lastAt': '2026-11-18T08:00:00Z',
      'resolvedAt': null, 'readAt': '2026-11-18T08:30:00Z', 'payload': {'score': 58, 'scoreChange': -15},
    },
  ];

  static Map<String, dynamic> _scan(String id, String status, {int devices = 0, String? completedAt,
          int? percent, String profile = 'STANDARD'}) =>
      {
        'id': id, 'homeId': 'h1', 'agentId': 'ag1', 'trigger': 'MANUAL', 'profile': profile, 'status': status,
        'requestedBy': 'u1', 'requestedAt': '2026-11-18T09:00:00Z', 'completedAt': completedAt,
        'cancelRequestedAt': null, 'progress': percent == null ? null : {'phase': 'PORTS', 'percent': percent},
        'devicesDiscovered': devices, 'outOfScopeDropped': 0, 'warnings': <String>[], 'failureReason': null,
      };

  static final overview = [
    {
      'homeId': 'h1', 'name': 'Casa MOCK', 'customerId': null,
      'security': {
        'score': 62, 'riskLevel': 'HIGH', 'rating': 'POOR', 'provisional': false, 'coverage': 0.9,
        'scoreChange': -15, 'computedAt': '2026-11-18T09:10:00Z', 'notComputedReason': null,
        'openFindings': {'HIGH': 1, 'MEDIUM': 2}, 'kevFindings': 1, 'devices': 2,
        'lastScanAt': '2026-11-18T09:10:00Z',
      },
    },
  ];

  static final devices = [
    {
      'id': 'd1', 'homeId': 'h1', 'mac': '00:11:22:33:44:55', 'macRandomized': false, 'ip': '192.168.60.1',
      'hostname': 'mock-router', 'manufacturer': 'MockNet', 'model': 'MR-1', 'os': null, 'category': 'ROUTER',
      'overallConfidence': 'HIGH', 'lastSeenAt': '2026-11-18T09:10:00Z',
      'services': {
        'ports': [
          {'protocol': 'TCP', 'port': 23, 'service': {'name': 'telnet', 'product': null, 'version': null}},
          {'protocol': 'TCP', 'port': 443, 'service': {'name': 'https', 'product': 'mock-httpd', 'version': '1.0'}},
        ],
      },
    },
    {
      'id': 'd2', 'homeId': 'h1', 'mac': '02:aa:bb:cc:dd:ee', 'macRandomized': true, 'ip': '192.168.60.9',
      'hostname': null, 'manufacturer': null, 'model': null, 'os': null, 'category': 'SMART_TV',
      'overallConfidence': 'MEDIUM', 'lastSeenAt': '2026-11-18T09:10:00Z', 'services': null,
    },
  ];

  /// Makes every access token invalid (as after their 15 minutes): the app must rotate.
  void expireAccessTokens() => _access.clear();

  bool called(String method, String path) => requests.any((r) => r.method == method && r.path == path);

  RecordedRequest last(String method, String path) =>
      requests.lastWhere((r) => r.method == method && r.path == path);

  Map<String, dynamic> _issue() {
    _seq++;
    final access = 'MOCK-access-$_seq';
    final refresh = 'MOCK-refresh-$_seq';
    _access.add(access);
    _refresh.add(refresh);
    return {
      'accessToken': access, 'tokenType': 'Bearer', 'expiresIn': 900, 'expiresAt': '2026-11-18T12:00:00Z',
      'sessionId': 'sess-1', 'refreshToken': refresh, 'refreshExpiresAt': '2026-12-02T12:00:00Z',
    };
  }

  static Map<String, dynamic> problem(int status, String code) =>
      {'type': 'about:blank', 'title': code, 'status': status, 'code': code, 'traceId': 'mock'};

  /// One API call: returns (status, JSON body).
  Future<(int, Object?)> handle(String method, String path, Map<String, String> query, Object? body,
      Map<String, String> headers) async {
    requests.add(RecordedRequest(method, path, query, body, headers));
    final json = body is Map ? Map<String, dynamic>.from(body) : const <String, dynamic>{};

    // --- public mobile auth ---
    if (path.startsWith('/api/v1/auth/mobile/')) {
      switch (path) {
        case '/api/v1/auth/mobile/login':
          return json['email'] == email && json['password'] == password
              ? (200, _issue())
              : (401, problem(401, 'INVALID_CREDENTIALS'));
        case '/api/v1/auth/mobile/refresh':
          final token = json['refreshToken'] as String?;
          if (token == null) {
            return (400, problem(400, 'VALIDATION_FAILED'));
          }
          if (sessionRevoked || _consumed.contains(token) || !_refresh.remove(token)) {
            _refresh.clear(); // reuse: the whole session is revoked
            _access.clear();
            return (401, problem(401, 'INVALID_REFRESH_TOKEN'));
          }
          _consumed.add(token);
          return (200, _issue());
        case '/api/v1/auth/mobile/logout':
          _refresh.remove(json['refreshToken']);
          _access.clear();
          return (204, null);
      }
    }

    final auth = headers['authorization'] ?? headers['Authorization'];
    if (auth == null || !auth.startsWith('Bearer ') || !_access.contains(auth.substring(7))) {
      return (401, problem(401, 'UNAUTHORIZED'));
    }

    final seg = path.split('/').where((s) => s.isNotEmpty).toList(); // api v1 ...
    final route = seg.skip(2).toList();
    switch ((method, route)) {
      case ('GET', ['me']):
        return (200, {
          'id': 'u1', 'email': email, 'displayName': 'Utente MOCK', 'locale': 'it', 'status': 'ACTIVE',
          'permissions': permissions.toList(), 'sessionId': 'sess-1', 'roles': <Object>[],
          'tenant': {'id': 't1', 'type': 'INDIVIDUAL', 'name': 'MOCK', 'organizationId': null},
        });
      case ('GET', ['overview']):
        return (200, permissions.contains('finding:read')
            ? overview
            : overview.map((h) => {...h, 'security': null}).toList());
      case ('GET', ['homes', 'h1', 'devices']):
        return (200, devices);
      case ('GET', ['devices', final id]):
        final d = devices.where((d) => d['id'] == id).firstOrNull;
        return d == null ? (404, problem(404, 'NOT_FOUND')) : (200, d);
      case ('GET', ['homes', 'h1', 'scans']):
        return (200, scans.reversed.toList());
      case ('POST', ['homes', 'h1', 'scans']):
        if (!permissions.contains('scan:create')) {
          return (403, problem(403, 'FORBIDDEN'));
        }
        if (scanError != null) {
          return (409, problem(409, scanError!));
        }
        final scan = _scan('s${scans.length + 1}', 'PENDING', profile: json['profile'] as String);
        scans.add(scan);
        return (202, scan);
      case ('GET', ['scans', final id]):
        final i = scans.indexWhere((s) => s['id'] == id);
        if (i < 0) {
          return (404, problem(404, 'NOT_FOUND'));
        }
        // each poll moves an active scan forward: QUEUED -> RUNNING 50% -> COMPLETED
        final polls = _scanPolls[id] = (_scanPolls[id] ?? 0) + 1;
        if (scans[i]['status'] != 'COMPLETED' && scans[i]['status'] != 'CANCELLED') {
          final profile = scans[i]['profile'] as String;
          scans[i] = switch (polls) {
            1 => _scan(id, 'QUEUED', profile: profile),
            2 => _scan(id, 'RUNNING', percent: 50, devices: 1, profile: profile),
            _ => _scan(id, 'COMPLETED', devices: 2, completedAt: '2026-11-18T11:00:00Z', profile: profile),
          };
        }
        return (200, scans[i]);
      case ('GET', ['alerts']):
        final unread = query['unread'] == 'true';
        return (200, alerts.where((a) => !unread || a['readAt'] == null).toList());
      case ('GET', ['alerts', 'unread-count']):
        return (200, {'count': alerts.where((a) => a['readAt'] == null).length});
      case ('POST', ['alerts', final id, 'read']):
        final a = alerts.where((a) => a['id'] == id).firstOrNull;
        if (a == null) {
          return (404, problem(404, 'NOT_FOUND'));
        }
        a['readAt'] = '2026-11-18T11:00:00Z';
        return (204, null);
      case ('POST', ['alerts', 'read-all']):
        final n = alerts.where((a) => a['readAt'] == null).length;
        for (final a in alerts) {
          a['readAt'] ??= '2026-11-18T11:00:00Z';
        }
        return (200, {'count': n});
      case ('POST', ['push-devices']):
        final id = 'p${pushRegistrations.length + 1}';
        pushRegistrations[id] = json;
        return (201, {'id': id, 'platform': json['platform'], 'locale': json['locale'], 'currentSession': true,
            'createdAt': '2026-11-18T11:00:00Z', 'lastSeenAt': '2026-11-18T11:00:00Z', 'pushEnabled': true});
      case ('DELETE', ['push-devices', final id]):
        return pushRegistrations.remove(id) == null ? (404, problem(404, 'NOT_FOUND')) : (204, null);
    }
    return (404, problem(404, 'NOT_FOUND'));
  }
}

class RecordedRequest {
  RecordedRequest(this.method, this.path, this.query, this.body, this.headers);

  final String method;
  final String path;
  final Map<String, String> query;
  final Object? body;
  final Map<String, String> headers;
}

/// Dio adapter calling [FakeBackend] in memory (widget tests: no sockets, no timers).
class FakeAdapter implements HttpClientAdapter {
  FakeAdapter(this.backend);

  final FakeBackend backend;

  @override
  Future<ResponseBody> fetch(RequestOptions options, Stream<Uint8List>? requestStream, Future<void>? cancelFuture) async {
    Object? body = options.data;
    if (body is String && body.isNotEmpty) {
      body = jsonDecode(body);
    }
    final headers = options.headers.map((k, v) => MapEntry(k.toLowerCase(), '$v'));
    final (status, json) = await backend.handle(options.method, options.uri.path,
        options.uri.queryParameters, body, headers);
    return ResponseBody.fromString(json == null ? '' : jsonEncode(json), status, headers: {
      Headers.contentTypeHeader: [Headers.jsonContentType],
    });
  }

  @override
  void close({bool force = false}) {}
}

/// The same fake served over real HTTP on localhost (integration test of the whole client stack).
class FakeHttpServer {
  FakeHttpServer._(this.backend, this._server);

  static Future<FakeHttpServer> start(FakeBackend backend) async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final fake = FakeHttpServer._(backend, server);
    server.listen(fake._serve);
    return fake;
  }

  final FakeBackend backend;
  final HttpServer _server;

  String get baseUrl => 'http://127.0.0.1:${_server.port}';

  Future<void> _serve(HttpRequest request) async {
    final text = await utf8.decodeStream(request);
    final headers = <String, String>{};
    request.headers.forEach((name, values) => headers[name.toLowerCase()] = values.join(','));
    final (status, json) = await backend.handle(request.method, request.uri.path, request.uri.queryParameters,
        text.isEmpty ? null : jsonDecode(text), headers);
    request.response.statusCode = status;
    if (json != null) {
      request.response.headers.contentType = ContentType.json;
      request.response.write(jsonEncode(json));
    }
    await request.response.close();
  }

  Future<void> close() => _server.close(force: true);
}
