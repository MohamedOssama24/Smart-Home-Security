import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

import '../test/integration/app_flow.dart';

/// The same flow on an emulator or device (`flutter test integration_test -d <device>`): the
/// [MOCK] API runs inside the test on the device loopback, no backend and no network needed.
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  testWidgets('app flow on device: login, dashboard, devices, manual scan, alerts, logout', runAppFlow);
}
