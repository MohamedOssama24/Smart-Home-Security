// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for English (`en`).
class AppLocalizationsEn extends AppLocalizations {
  AppLocalizationsEn([String locale = 'en']) : super(locale);

  @override
  String get appTitle => 'Smart Home Security Check';

  @override
  String get loginTitle => 'Sign in';

  @override
  String get email => 'Email';

  @override
  String get password => 'Password';

  @override
  String get signIn => 'Sign in';

  @override
  String get loginInvalid => 'Incorrect email or password.';

  @override
  String get loginLocked => 'Too many attempts. Try again in a few minutes.';

  @override
  String get networkError => 'Cannot reach the server. Check your connection.';

  @override
  String get genericError => 'Something went wrong. Please try again.';

  @override
  String get sessionExpired =>
      'Your session has expired: please sign in again.';

  @override
  String get fieldRequired => 'Required';

  @override
  String get retry => 'Retry';

  @override
  String get logout => 'Sign out';

  @override
  String get homes => 'Homes';

  @override
  String get noHomes => 'No homes yet. Add one from the web dashboard.';

  @override
  String get alerts => 'Alerts';

  @override
  String get score => 'Security score';

  @override
  String scoreValue(int score) {
    return '$score/100';
  }

  @override
  String scoreChange(int change) {
    String _temp0 = intl.Intl.pluralLogic(
      change,
      locale: localeName,
      other: '$change points since last time',
      zero: 'unchanged',
    );
    return '$_temp0';
  }

  @override
  String get notComputed => 'Score not computed';

  @override
  String get notComputedDiscovery =>
      'A Quick or Standard scan is needed to compute it.';

  @override
  String get provisional => 'Provisional: low analysis coverage';

  @override
  String openFindings(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count open issues',
      one: '1 open issue',
      zero: 'No open issues',
    );
    return '$_temp0';
  }

  @override
  String kevFindings(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count actively exploited vulnerabilities',
      one: '1 actively exploited vulnerability',
    );
    return '$_temp0';
  }

  @override
  String devicesCount(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count devices',
      one: '1 device',
      zero: 'No devices',
    );
    return '$_temp0';
  }

  @override
  String lastScan(String date) {
    return 'Last scan: $date';
  }

  @override
  String get neverScanned => 'No completed scan';

  @override
  String get noSecurityAccess =>
      'Your role does not allow viewing security data.';

  @override
  String riskLevel(String level) {
    String _temp0 = intl.Intl.selectLogic(level, {
      'LOW': 'Low risk',
      'MEDIUM': 'Medium risk',
      'HIGH': 'High risk',
      'CRITICAL': 'Critical risk',
      'other': '-',
    });
    return '$_temp0';
  }

  @override
  String severity(String severity) {
    String _temp0 = intl.Intl.selectLogic(severity, {
      'CRITICAL': 'Critical',
      'HIGH': 'High',
      'MEDIUM': 'Medium',
      'LOW': 'Low',
      'INFO': 'Informational',
      'INFORMATIONAL': 'Informational',
      'other': '-',
    });
    return '$_temp0';
  }

  @override
  String get devices => 'Devices';

  @override
  String get noDevices => 'No devices found. Start a scan.';

  @override
  String get deviceIp => 'IP address';

  @override
  String get deviceMac => 'MAC address';

  @override
  String get deviceManufacturer => 'Manufacturer';

  @override
  String get deviceModel => 'Model';

  @override
  String get deviceOs => 'Operating system';

  @override
  String get deviceCategory => 'Type';

  @override
  String get deviceConfidence => 'Confidence';

  @override
  String get deviceLastSeen => 'Last seen';

  @override
  String get randomizedMac => 'Random MAC (device privacy)';

  @override
  String get openPorts => 'Services exposed on the network';

  @override
  String get noOpenPorts => 'No open port found by the last port scan.';

  @override
  String confidence(String level) {
    String _temp0 = intl.Intl.selectLogic(level, {
      'HIGH': 'High',
      'MEDIUM': 'Medium',
      'LOW': 'Low',
      'other': '-',
    });
    return '$_temp0';
  }

  @override
  String category(String category) {
    String _temp0 = intl.Intl.selectLogic(category, {
      'ROUTER': 'Router',
      'IP_CAMERA': 'Camera',
      'SMART_TV': 'Smart TV',
      'SMARTPHONE': 'Smartphone',
      'TABLET': 'Tablet',
      'LAPTOP': 'Laptop',
      'DESKTOP': 'Computer',
      'PRINTER': 'Printer',
      'NAS': 'NAS',
      'SMART_PLUG': 'Smart plug',
      'SMART_SPEAKER': 'Smart speaker',
      'IOT': 'IoT device',
      'other': 'Unidentified',
    });
    return '$_temp0';
  }

  @override
  String get scans => 'Scans';

  @override
  String get noScans => 'No scans.';

  @override
  String get newScan => 'New scan';

  @override
  String scanProfile(String profile) {
    String _temp0 = intl.Intl.selectLogic(profile, {
      'DISCOVERY': 'Discovery',
      'QUICK': 'Quick',
      'STANDARD': 'Standard',
      'other': '$profile',
    });
    return '$_temp0';
  }

  @override
  String scanProfileHelp(String profile) {
    String _temp0 = intl.Intl.selectLogic(profile, {
      'DISCOVERY':
          'Finds the devices on the network, without checking services.',
      'QUICK': 'Devices and the most common ports: a few minutes.',
      'STANDARD': 'Devices, ports and services: full analysis.',
      'other': '',
    });
    return '$_temp0';
  }

  @override
  String get scanConfirm =>
      'The scan is run by the agent installed at home, only on the networks you authorized and without any attempt to log into the devices.';

  @override
  String get start => 'Start';

  @override
  String get cancel => 'Cancel';

  @override
  String get stopScan => 'Stop';

  @override
  String scanStatus(String status) {
    String _temp0 = intl.Intl.selectLogic(status, {
      'PENDING': 'Pending',
      'QUEUED': 'Queued',
      'RUNNING': 'Running',
      'COMPLETED': 'Completed',
      'COMPLETED_WITH_WARNINGS': 'Completed with warnings',
      'FAILED': 'Failed',
      'CANCELLED': 'Cancelled',
      'other': '$status',
    });
    return '$_temp0';
  }

  @override
  String scanProgress(int percent) {
    return '$percent%';
  }

  @override
  String scanDevices(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count devices found',
      one: '1 device found',
      zero: 'No devices found',
    );
    return '$_temp0';
  }

  @override
  String scanFailure(String reason) {
    return 'Reason: $reason';
  }

  @override
  String get scanCancelRequested => 'Cancellation requested';

  @override
  String scanError(String code) {
    String _temp0 = intl.Intl.selectLogic(code, {
      'NO_AUTHORIZED_NETWORK':
          'No authorized network: authorize it from the web dashboard.',
      'AGENT_OFFLINE': 'The home\'s agent is not reachable.',
      'SCAN_ALREADY_ACTIVE': 'A scan is already running.',
      'PROFILE_NOT_AVAILABLE': 'Profile not available for this agent.',
      'other': 'The scan could not be started.',
    });
    return '$_temp0';
  }

  @override
  String alertTitle(String type) {
    String _temp0 = intl.Intl.selectLogic(type, {
      'NEW_FINDING': 'New security issue',
      'FINDING_RESOLVED': 'Issue resolved',
      'SCORE_DROPPED': 'The score dropped',
      'NEW_DEVICE': 'New device on the network',
      'SCAN_FAILED': 'Scan failed',
      'AGENT_OFFLINE': 'Agent not reachable',
      'other': 'Alert',
    });
    return '$_temp0';
  }

  @override
  String alertScore(int score, int change) {
    return 'Now $score/100 ($change points)';
  }

  @override
  String alertDevices(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count new devices',
      one: '1 new device',
    );
    return '$_temp0';
  }

  @override
  String alertAgent(String name) {
    return 'Agent \"$name\" silent for more than 15 minutes';
  }

  @override
  String occurrences(int count) {
    return 'Repeated $count times';
  }

  @override
  String get resolved => 'Resolved';

  @override
  String get markRead => 'Mark as read';

  @override
  String get markAllRead => 'Mark all as read';

  @override
  String get unreadOnly => 'Unread only';

  @override
  String get noAlerts => 'No alerts.';

  @override
  String get pushDisabled =>
      'Push notifications are not configured in this build.';

  @override
  String get viewDevices => 'Devices';

  @override
  String get viewScans => 'Scans';
}
