/// API models (read-only views of the backend JSON, docs/05-API.md). Unknown fields are ignored.
library;

DateTime? _date(Object? v) => v is String ? DateTime.tryParse(v)?.toLocal() : null;

int _int(Object? v) => v is num ? v.toInt() : 0;

class Me {
  Me({
    required this.id,
    required this.displayName,
    required this.email,
    required this.locale,
    required this.permissions,
    required this.sessionId,
  });

  factory Me.fromJson(Map<String, dynamic> j) => Me(
    id: j['id'] as String,
    displayName: j['displayName'] as String? ?? '',
    email: j['email'] as String? ?? '',
    locale: j['locale'] as String? ?? 'it',
    permissions: Set<String>.from(j['permissions'] as List? ?? const []),
    sessionId: j['sessionId'] as String? ?? '',
  );

  final String id;
  final String displayName;
  final String email;
  final String locale;
  final Set<String> permissions;
  final String sessionId;

  bool can(String permission) => permissions.contains(permission);
}

class HomeSecurity {
  HomeSecurity({
    this.score,
    this.riskLevel,
    this.rating,
    required this.provisional,
    this.coverage,
    this.scoreChange,
    this.notComputedReason,
    required this.openFindings,
    required this.kevFindings,
    required this.devices,
    this.lastScanAt,
  });

  factory HomeSecurity.fromJson(Map<String, dynamic> j) => HomeSecurity(
    score: (j['score'] as num?)?.toInt(),
    riskLevel: j['riskLevel'] as String?,
    rating: j['rating'] as String?,
    provisional: j['provisional'] == true,
    coverage: (j['coverage'] as num?)?.toDouble(),
    scoreChange: (j['scoreChange'] as num?)?.toInt(),
    notComputedReason: j['notComputedReason'] as String?,
    openFindings: (j['openFindings'] as Map? ?? const {}).map((k, v) => MapEntry(k as String, _int(v))),
    kevFindings: _int(j['kevFindings']),
    devices: _int(j['devices']),
    lastScanAt: _date(j['lastScanAt']),
  );

  final int? score;
  final String? riskLevel;
  final String? rating;
  final bool provisional;
  final double? coverage;
  final int? scoreChange;
  final String? notComputedReason;
  final Map<String, int> openFindings;
  final int kevFindings;
  final int devices;
  final DateTime? lastScanAt;

  int get openTotal => openFindings.values.fold(0, (a, b) => a + b);
}

class HomeOverview {
  HomeOverview({required this.homeId, required this.name, this.security});

  factory HomeOverview.fromJson(Map<String, dynamic> j) => HomeOverview(
    homeId: j['homeId'] as String,
    name: j['name'] as String? ?? '',
    security: j['security'] is Map ? HomeSecurity.fromJson(Map<String, dynamic>.from(j['security'] as Map)) : null,
  );

  final String homeId;
  final String name;
  final HomeSecurity? security;
}

class OpenPort {
  OpenPort({required this.protocol, required this.port, this.service, this.product, this.version});

  factory OpenPort.fromJson(Map<String, dynamic> j) {
    final s = j['service'] as Map?;
    return OpenPort(
      protocol: j['protocol'] as String? ?? 'TCP',
      port: _int(j['port']),
      service: s?['name'] as String?,
      product: s?['product'] as String?,
      version: s?['version'] as String?,
    );
  }

  final String protocol;
  final int port;
  final String? service;
  final String? product;
  final String? version;
}

class Device {
  Device({
    required this.id,
    required this.homeId,
    this.ip,
    this.mac,
    this.hostname,
    this.manufacturer,
    this.model,
    this.os,
    required this.category,
    required this.confidence,
    required this.macRandomized,
    this.lastSeenAt,
    required this.ports,
    this.interfaces = const [],
    this.addressHistory = const [],
    this.customName,
    this.identity = const [],
    this.identificationHistory = const [],
  });

  factory Device.fromJson(Map<String, dynamic> j) => Device(
    id: j['id'] as String,
    homeId: j['homeId'] as String? ?? '',
    ip: j['ip'] as String?,
    mac: j['mac'] as String?,
    hostname: j['hostname'] as String?,
    manufacturer: j['manufacturer'] as String?,
    model: j['model'] as String?,
    os: j['os'] as String?,
    category: j['category'] as String? ?? 'UNKNOWN_DEVICE',
    confidence: j['overallConfidence'] as String? ?? 'LOW',
    macRandomized: j['macRandomized'] == true,
    lastSeenAt: _date(j['lastSeenAt']),
    ports: ((j['services'] as Map?)?['ports'] as List? ?? const [])
        .map((p) => OpenPort.fromJson(Map<String, dynamic>.from(p as Map)))
        .toList(),
    interfaces: (j['interfaces'] as List? ?? const [])
        .map((i) => DeviceInterface.fromJson(Map<String, dynamic>.from(i as Map)))
        .toList(),
    addressHistory: (j['addressHistory'] as List? ?? const [])
        .map((a) => DeviceAddress.fromJson(Map<String, dynamic>.from(a as Map)))
        .toList(),
    customName: j['customName'] as String?,
    identity: (j['identity'] as List? ?? const [])
        .map((f) => IdentityField.fromJson(Map<String, dynamic>.from(f as Map)))
        .toList(),
    identificationHistory: (j['identificationHistory'] as List? ?? const [])
        .map((c) => IdentificationChange.fromJson(Map<String, dynamic>.from(c as Map)))
        .toList(),
  );

  final String id;
  final String homeId;
  final String? ip;
  final String? mac;
  final String? hostname;
  final String? manufacturer;
  final String? model;
  final String? os;
  final String category;
  final String confidence;
  final bool macRandomized;
  final DateTime? lastSeenAt;
  final List<OpenPort> ports;

  /// Every MAC of the device (detail only, M19).
  final List<DeviceInterface> interfaces;

  /// IPv4/IPv6 address history, most recently seen first (detail only, M19).
  final List<DeviceAddress> addressHistory;

  /// Name given by the user (M20), never changed by scans.
  final String? customName;

  /// Fields of the device card with status VERIFIED/PROBABLE/UNKNOWN (detail only, M20).
  final List<IdentityField> identity;

  /// Changes of value or status of the identity fields, newest first (detail only, M20).
  final List<IdentificationChange> identificationHistory;

  String get name =>
      customName ?? hostname ?? [manufacturer, model].whereType<String>().join(' ').trim().ifEmpty(ip ?? id);
}

/// One field of the device card (M20): [sources] are the agreeing sources (USER when confirmed by the user).
class IdentityField {
  IdentityField({
    required this.field,
    this.value,
    required this.status,
    this.confidence,
    this.sources = const [],
    this.userConfirmed = false,
    this.conflict = false,
  });

  factory IdentityField.fromJson(Map<String, dynamic> j) => IdentityField(
    field: j['field'] as String,
    value: j['value'] as String?,
    status: j['status'] as String? ?? 'UNKNOWN',
    confidence: j['confidence'] as String?,
    sources: (j['sources'] as List? ?? const []).map((s) => s.toString()).toList(),
    userConfirmed: j['userConfirmed'] == true,
    conflict: j['conflict'] == true,
  );

  final String field;
  final String? value;
  final String status;
  final String? confidence;
  final List<String> sources;
  final bool userConfirmed;
  final bool conflict;
}

/// A change of value or status of an identity field; [origin] SCAN or USER.
class IdentificationChange {
  IdentificationChange({
    required this.field,
    this.oldValue,
    this.newValue,
    this.newStatus,
    required this.origin,
    this.changedAt,
  });

  factory IdentificationChange.fromJson(Map<String, dynamic> j) => IdentificationChange(
    field: j['field'] as String,
    oldValue: j['oldValue'] as String?,
    newValue: j['newValue'] as String?,
    newStatus: j['newStatus'] as String?,
    origin: j['origin'] as String? ?? 'SCAN',
    changedAt: _date(j['changedAt']),
  );

  final String field;
  final String? oldValue;
  final String? newValue;
  final String? newStatus;
  final String origin;
  final DateTime? changedAt;
}

/// One network interface (MAC) of a device; [current]: seen by the last scan of the device.
class DeviceInterface {
  DeviceInterface({
    required this.mac,
    required this.macRandomized,
    this.vendor,
    this.agentInterface,
    required this.current,
  });

  factory DeviceInterface.fromJson(Map<String, dynamic> j) => DeviceInterface(
    mac: j['mac'] as String,
    macRandomized: j['macRandomized'] == true,
    vendor: j['vendor'] as String?,
    agentInterface: j['agentInterface'] as String?,
    current: j['current'] == true,
  );

  final String mac;
  final bool macRandomized;
  final String? vendor;
  final String? agentInterface;
  final bool current;
}

/// One address of the history: [interfaceId] EUI64 (embeds the MAC) or RANDOM (temporary IPv6).
class DeviceAddress {
  DeviceAddress({
    required this.address,
    required this.family,
    this.scope,
    this.interfaceId,
    required this.current,
    this.lastSeenAt,
  });

  factory DeviceAddress.fromJson(Map<String, dynamic> j) => DeviceAddress(
    address: j['address'] as String,
    family: (j['family'] as num?)?.toInt() ?? 4,
    scope: j['scope'] as String?,
    interfaceId: j['interfaceId'] as String?,
    current: j['current'] == true,
    lastSeenAt: _date(j['lastSeenAt']),
  );

  final String address;
  final int family;
  final String? scope;
  final String? interfaceId;
  final bool current;
  final DateTime? lastSeenAt;
}

extension on String {
  String ifEmpty(String other) => isEmpty ? other : this;
}

const activeScanStatuses = {'PENDING', 'QUEUED', 'RUNNING'};

class Scan {
  Scan({
    required this.id,
    required this.homeId,
    required this.profile,
    required this.status,
    this.requestedAt,
    this.completedAt,
    this.phase,
    this.percent,
    required this.devicesDiscovered,
    this.failureReason,
    required this.warnings,
    this.cancelRequestedAt,
  });

  factory Scan.fromJson(Map<String, dynamic> j) {
    final progress = j['progress'] as Map?;
    return Scan(
      id: j['id'] as String,
      homeId: j['homeId'] as String? ?? '',
      profile: j['profile'] as String? ?? '',
      status: j['status'] as String? ?? 'PENDING',
      requestedAt: _date(j['requestedAt']),
      completedAt: _date(j['completedAt']),
      phase: progress?['phase'] as String?,
      percent: (progress?['percent'] as num?)?.toInt(),
      devicesDiscovered: _int(j['devicesDiscovered']),
      failureReason: j['failureReason'] as String?,
      warnings: List<String>.from(j['warnings'] as List? ?? const []),
      cancelRequestedAt: _date(j['cancelRequestedAt']),
    );
  }

  final String id;
  final String homeId;
  final String profile;
  final String status;
  final DateTime? requestedAt;
  final DateTime? completedAt;
  final String? phase;
  final int? percent;
  final int devicesDiscovered;
  final String? failureReason;
  final List<String> warnings;
  final DateTime? cancelRequestedAt;

  bool get active => activeScanStatuses.contains(status);
}

class AlertItem {
  AlertItem({
    required this.id,
    required this.homeId,
    required this.homeName,
    this.deviceId,
    required this.type,
    required this.severity,
    required this.occurrences,
    this.lastAt,
    this.resolvedAt,
    this.readAt,
    required this.payload,
  });

  factory AlertItem.fromJson(Map<String, dynamic> j) => AlertItem(
    id: j['id'] as String,
    homeId: j['homeId'] as String? ?? '',
    homeName: j['homeName'] as String? ?? '',
    deviceId: j['deviceId'] as String?,
    type: j['type'] as String? ?? '',
    severity: j['severity'] as String? ?? 'INFO',
    occurrences: _int(j['occurrences']),
    lastAt: _date(j['lastAt']),
    resolvedAt: _date(j['resolvedAt']),
    readAt: _date(j['readAt']),
    payload: Map<String, dynamic>.from(j['payload'] as Map? ?? const {}),
  );

  final String id;
  final String homeId;
  final String homeName;
  final String? deviceId;
  final String type;
  final String severity;
  final int occurrences;
  final DateTime? lastAt;
  final DateTime? resolvedAt;
  final DateTime? readAt;
  final Map<String, dynamic> payload;

  bool get unread => readAt == null;

  AlertItem markedRead() => AlertItem(
    id: id,
    homeId: homeId,
    homeName: homeName,
    deviceId: deviceId,
    type: type,
    severity: severity,
    occurrences: occurrences,
    lastAt: lastAt,
    resolvedAt: resolvedAt,
    readAt: DateTime.now(),
    payload: payload,
  );
}

/// A person of the home associated with a device (M24): PROBABLE from an automatic source
/// (device name, Home Assistant, directory, firewall), CONFIRMED by a user. Read-only in the app.
class DevicePerson {
  DevicePerson({
    required this.personId,
    required this.name,
    required this.deviceId,
    required this.status,
    required this.source,
    this.evidence,
  });

  final String personId;
  final String name;
  final String deviceId;
  final String status;
  final String source;
  final String? evidence;

  /// Flattens GET /homes/{id}/people into one entry per (person, device).
  static List<DevicePerson> fromPeople(List<dynamic> people) => [
    for (final p in people.cast<Map>())
      for (final d in (p['devices'] as List? ?? const []).cast<Map>())
        DevicePerson(
          personId: p['id'] as String,
          name: p['name'] as String,
          deviceId: d['deviceId'] as String,
          status: d['status'] as String? ?? 'PROBABLE',
          source: d['source'] as String? ?? 'USER',
          evidence: d['evidence'] as String?,
        ),
  ];
}
