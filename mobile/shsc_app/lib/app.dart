import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import 'core/providers.dart';
import 'core/push/push_messaging.dart';
import 'l10n/app_localizations.dart';
import 'ui/alerts_page.dart';
import 'ui/device_page.dart';
import 'ui/devices_page.dart';
import 'ui/home_page.dart';
import 'ui/login_page.dart';
import 'ui/overview_page.dart';
import 'ui/scan_page.dart';
import 'ui/scans_page.dart';

final messengerKey = GlobalKey<ScaffoldMessengerState>();

final routerProvider = Provider<GoRouter>((ref) {
  final auth = ValueNotifier<AuthState>(ref.read(authProvider));
  ref.listen(authProvider, (_, next) => auth.value = next);
  ref.onDispose(auth.dispose);
  return GoRouter(
    initialLocation: '/',
    refreshListenable: auth,
    redirect: (context, state) {
      final where = state.matchedLocation;
      return switch (auth.value) {
        AuthRestoring() => where == '/splash' ? null : '/splash',
        SignedOut() => where == '/login' ? null : '/login',
        SignedIn() => where == '/login' || where == '/splash' ? '/' : null,
      };
    },
    routes: [
      GoRoute(path: '/splash', builder: (_, _) => const Scaffold(body: Center(child: CircularProgressIndicator()))),
      GoRoute(path: '/login', builder: (_, _) => const LoginPage()),
      GoRoute(path: '/', builder: (_, _) => const OverviewPage()),
      GoRoute(path: '/alerts', builder: (_, _) => const AlertsPage()),
      GoRoute(path: '/homes/:id', builder: (_, s) => HomePage(homeId: s.pathParameters['id']!)),
      GoRoute(path: '/homes/:id/devices', builder: (_, s) => DevicesPage(homeId: s.pathParameters['id']!)),
      GoRoute(path: '/homes/:id/scans', builder: (_, s) => ScansPage(homeId: s.pathParameters['id']!)),
      GoRoute(path: '/devices/:id', builder: (_, s) => DevicePage(deviceId: s.pathParameters['id']!)),
      GoRoute(path: '/scans/:id', builder: (_, s) => ScanPage(scanId: s.pathParameters['id']!)),
    ],
  );
});

class ShscApp extends ConsumerStatefulWidget {
  const ShscApp({super.key});

  @override
  ConsumerState<ShscApp> createState() => _ShscAppState();
}

class _ShscAppState extends ConsumerState<ShscApp> {
  final _subscriptions = <StreamSubscription<PushMessage>>[];

  @override
  void initState() {
    super.initState();
    final push = ref.read(pushMessagingProvider);
    // a tapped notification opens the alerts; one received in the foreground refreshes them
    _subscriptions.add(push.opened.listen(_open));
    _subscriptions.add(push.foreground.listen((m) {
      ref.invalidate(unreadCountProvider);
      ref.invalidate(alertsProvider);
      if (m.title != null) {
        messengerKey.currentState?.showSnackBar(SnackBar(content: Text(m.title!)));
      }
    }));
    push.initialMessage().then((m) => m == null ? null : _open(m));
  }

  void _open(PushMessage m) {
    ref.invalidate(unreadCountProvider);
    ref.read(routerProvider).go('/alerts');
  }

  @override
  void dispose() {
    for (final s in _subscriptions) {
      s.cancel();
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp.router(
      onGenerateTitle: (c) => AppLocalizations.of(c).appTitle,
      scaffoldMessengerKey: messengerKey,
      theme: ThemeData(colorSchemeSeed: const Color(0xFF1A73E8), useMaterial3: true),
      darkTheme: ThemeData(colorSchemeSeed: const Color(0xFF1A73E8), brightness: Brightness.dark, useMaterial3: true),
      supportedLocales: AppLocalizations.supportedLocales,
      localizationsDelegates: const [
        AppLocalizations.delegate,
        GlobalMaterialLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
      ],
      localeResolutionCallback: (locale, supported) =>
          supported.firstWhere((l) => l.languageCode == locale?.languageCode, orElse: () => const Locale('it')),
      routerConfig: ref.watch(routerProvider),
    );
  }
}
