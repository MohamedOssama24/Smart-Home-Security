import 'package:flutter_test/flutter_test.dart';

import 'app_flow.dart';

/// Integration test on the Dart VM (CI): the whole app over real HTTP on localhost.
void main() {
  testWidgets('app flow over HTTP: login, dashboard, devices, manual scan, alerts, logout', runAppFlow);
}
