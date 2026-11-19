import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../core/api/models.dart';
import '../core/providers.dart';
import 'common.dart';

/// Start page: the homes the user can see, most at risk first (GET /overview, docs/21 §2).
class OverviewPage extends ConsumerWidget {
  const OverviewPage({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = context.l10n;
    final homes = ref.watch(overviewProvider);
    return Scaffold(
      appBar: AppBar(
        title: Text(l10n.homes),
        actions: [
          const AlertsButton(),
          PopupMenuButton<String>(
            key: const Key('menu'),
            onSelected: (_) => ref.read(authProvider.notifier).logout(),
            itemBuilder: (_) => [PopupMenuItem(key: const Key('logout'), value: 'logout', child: Text(l10n.logout))],
          ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: () => ref.refresh(overviewProvider.future),
        child: AsyncBody(
          value: homes,
          onRetry: () => ref.invalidate(overviewProvider),
          data: (list) => list.isEmpty
              ? ListView(children: [Padding(padding: const EdgeInsets.all(24), child: Text(l10n.noHomes))])
              : ListView.builder(
                  padding: const EdgeInsets.all(8),
                  itemCount: list.length,
                  itemBuilder: (_, i) => HomeCard(home: list[i]),
                ),
        ),
      ),
    );
  }
}

class AlertsButton extends ConsumerWidget {
  const AlertsButton({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final count = ref.watch(unreadCountProvider).value ?? 0;
    return IconButton(
      key: const Key('alerts'),
      tooltip: context.l10n.alerts,
      onPressed: () => context.push('/alerts'),
      icon: Badge(
        isLabelVisible: count > 0,
        label: Text('$count', key: const Key('unread-count')),
        child: const Icon(Icons.notifications_outlined),
      ),
    );
  }
}

class HomeCard extends StatelessWidget {
  const HomeCard({super.key, required this.home});

  final HomeOverview home;

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    final s = home.security;
    return Card(
      key: Key('home-${home.homeId}'),
      child: ListTile(
        onTap: () => context.push('/homes/${home.homeId}'),
        title: Text(home.name, style: const TextStyle(fontWeight: FontWeight.w600)),
        subtitle: Padding(
          padding: const EdgeInsets.only(top: 4),
          child: s == null
              ? Text(l10n.noSecurityAccess)
              : Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(l10n.openFindings(s.openTotal)),
                  Text(l10n.devicesCount(s.devices)),
                  Text(s.lastScanAt == null ? l10n.neverScanned : l10n.lastScan(context.formatDate(s.lastScanAt))),
                ]),
        ),
        trailing: s == null ? null : ScoreBadge(security: s),
      ),
    );
  }
}

class ScoreBadge extends StatelessWidget {
  const ScoreBadge({super.key, required this.security});

  final HomeSecurity security;

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    if (security.score == null) {
      return Text('—', semanticsLabel: l10n.notComputed, style: Theme.of(context).textTheme.headlineSmall);
    }
    return Column(mainAxisAlignment: MainAxisAlignment.center, children: [
      Text('${security.score}', key: const Key('score'),
          style: Theme.of(context).textTheme.headlineSmall?.copyWith(color: severityColor(security.riskLevel))),
      Text(l10n.riskLevel(security.riskLevel ?? ''), style: Theme.of(context).textTheme.labelSmall),
    ]);
  }
}
