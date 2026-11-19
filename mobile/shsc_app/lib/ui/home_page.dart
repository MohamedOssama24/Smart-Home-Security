import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../core/api/models.dart';
import '../core/providers.dart';
import 'common.dart';
import 'overview_page.dart';

/// Dashboard of one home: score, issues by severity, devices and last scan.
class HomePage extends ConsumerWidget {
  const HomePage({super.key, required this.homeId});

  final String homeId;

  static const _severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'];

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = context.l10n;
    final homes = ref.watch(overviewProvider);
    final home = homes.value?.where((h) => h.homeId == homeId).firstOrNull;
    return Scaffold(
      appBar: AppBar(title: Text(home?.name ?? ''), actions: const [AlertsButton()]),
      body: RefreshIndicator(
        onRefresh: () => ref.refresh(overviewProvider.future),
        child: AsyncBody(
          value: homes,
          onRetry: () => ref.invalidate(overviewProvider),
          data: (_) => ListView(padding: const EdgeInsets.all(16), children: [
            if (home?.security case final s?) ...[
              _ScoreCard(security: s),
              const SizedBox(height: 12),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Text(l10n.openFindings(s.openTotal), style: Theme.of(context).textTheme.titleMedium),
                    const SizedBox(height: 8),
                    Wrap(spacing: 8, runSpacing: 8, children: [
                      for (final sev in _severities)
                        if ((s.openFindings[sev] ?? 0) > 0)
                          SeverityChip('${l10n.severity(sev)}: ${s.openFindings[sev]}', sev),
                    ]),
                    if (s.kevFindings > 0) ...[
                      const SizedBox(height: 8),
                      Text(l10n.kevFindings(s.kevFindings), style: TextStyle(color: severityColor('CRITICAL'))),
                    ],
                    const SizedBox(height: 8),
                    Text(l10n.devicesCount(s.devices)),
                    Text(s.lastScanAt == null ? l10n.neverScanned : l10n.lastScan(context.formatDate(s.lastScanAt))),
                  ]),
                ),
              ),
            ] else
              Text(l10n.noSecurityAccess),
            const SizedBox(height: 16),
            if (ref.watch(canProvider('device:read')))
              ListTile(
                key: const Key('open-devices'),
                leading: const Icon(Icons.devices_other),
                title: Text(l10n.viewDevices),
                trailing: const Icon(Icons.chevron_right),
                onTap: () => context.push('/homes/$homeId/devices'),
              ),
            if (ref.watch(canProvider('scan:read')))
              ListTile(
                key: const Key('open-scans'),
                leading: const Icon(Icons.radar),
                title: Text(l10n.viewScans),
                trailing: const Icon(Icons.chevron_right),
                onTap: () => context.push('/homes/$homeId/scans'),
              ),
          ]),
        ),
      ),
    );
  }
}

class _ScoreCard extends StatelessWidget {
  const _ScoreCard({required this.security});

  final HomeSecurity security;

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    final s = security;
    final text = Theme.of(context).textTheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(l10n.score, style: text.titleMedium),
          const SizedBox(height: 8),
          if (s.score == null) ...[
            Text(l10n.notComputed, key: const Key('score-missing'), style: text.headlineSmall),
            if (s.notComputedReason == 'PORT_SCAN_REQUIRED') Text(l10n.notComputedDiscovery),
          ] else ...[
            Text(l10n.scoreValue(s.score!), key: const Key('home-score'),
                style: text.displaySmall?.copyWith(color: severityColor(s.riskLevel))),
            Text(l10n.riskLevel(s.riskLevel ?? '')),
            if (s.scoreChange != null) Text(l10n.scoreChange(s.scoreChange!)),
            if (s.provisional) Text(l10n.provisional, style: TextStyle(color: severityColor('MEDIUM'))),
          ],
        ]),
      ),
    );
  }
}
