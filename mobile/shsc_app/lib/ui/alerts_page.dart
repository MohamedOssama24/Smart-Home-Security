import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../core/api/models.dart';
import '../core/providers.dart';
import 'common.dart';

/// The user's alerts (the dashboard inbox, docs/22 §1): text built from the payload, read state,
/// link to the home.
class AlertsPage extends ConsumerStatefulWidget {
  const AlertsPage({super.key});

  @override
  ConsumerState<AlertsPage> createState() => _AlertsPageState();
}

class _AlertsPageState extends ConsumerState<AlertsPage> {
  bool _unreadOnly = false;

  Future<void> _read(AlertItem a) async {
    if (a.unread) {
      await ref.read(apiProvider).markRead(a.id);
      ref.invalidate(alertsProvider);
      ref.invalidate(unreadCountProvider);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    final alerts = ref.watch(alertsProvider(_unreadOnly));
    return Scaffold(
      appBar: AppBar(
        title: Text(l10n.alerts),
        actions: [
          IconButton(
            key: const Key('read-all'),
            tooltip: l10n.markAllRead,
            icon: const Icon(Icons.done_all),
            onPressed: () async {
              await ref.read(apiProvider).markAllRead();
              ref.invalidate(alertsProvider);
              ref.invalidate(unreadCountProvider);
            },
          ),
        ],
      ),
      body: Column(children: [
        SwitchListTile(
          key: const Key('unread-only'),
          title: Text(l10n.unreadOnly),
          value: _unreadOnly,
          onChanged: (v) => setState(() => _unreadOnly = v),
        ),
        Expanded(
          child: RefreshIndicator(
            onRefresh: () => ref.refresh(alertsProvider(_unreadOnly).future),
            child: AsyncBody(
              value: alerts,
              onRetry: () => ref.invalidate(alertsProvider(_unreadOnly)),
              data: (list) => list.isEmpty
                  ? ListView(children: [Padding(padding: const EdgeInsets.all(24), child: Text(l10n.noAlerts))])
                  : ListView.separated(
                      itemCount: list.length,
                      separatorBuilder: (_, _) => const Divider(height: 1),
                      itemBuilder: (_, i) => _AlertTile(alert: list[i], onRead: _read),
                    ),
            ),
          ),
        ),
      ]),
    );
  }
}

class _AlertTile extends StatelessWidget {
  const _AlertTile({required this.alert, required this.onRead});

  final AlertItem alert;
  final Future<void> Function(AlertItem) onRead;

  /// Detail line from the payload: only what the dashboard shows (no evidence).
  static String detail(BuildContext context, AlertItem a) {
    final l10n = context.l10n;
    final p = a.payload;
    String? device() => p['deviceName'] == null ? null : '${p['deviceName']} (${p['deviceIp'] ?? ''})';
    return switch (a.type) {
      'NEW_FINDING' || 'FINDING_RESOLVED' =>
        [l10n.severity(p['findingSeverity'] as String? ?? a.severity), device()].whereType<String>().join(' · '),
      'SCORE_DROPPED' => l10n.alertScore((p['score'] as num?)?.toInt() ?? 0, (p['scoreChange'] as num?)?.toInt() ?? 0),
      'NEW_DEVICE' => ((p['count'] as num?)?.toInt() ?? 1) > 1
          ? l10n.alertDevices((p['count'] as num).toInt())
          : ((p['devices'] as List?)?.firstOrNull as Map?)?['name'] as String? ?? '',
      'SCAN_FAILED' => p['reason'] == null ? '' : l10n.scanFailure(p['reason'] as String),
      'AGENT_OFFLINE' => l10n.alertAgent(p['agentName'] as String? ?? ''),
      _ => '',
    };
  }

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    final a = alert;
    return ListTile(
      key: Key('alert-${a.id}'),
      tileColor: a.unread ? Theme.of(context).colorScheme.primaryContainer.withValues(alpha: 0.35) : null,
      leading: Icon(Icons.circle, size: 12, color: severityColor(a.severity)),
      title: Text(l10n.alertTitle(a.type), key: const Key('alert-title'),
          style: TextStyle(fontWeight: a.unread ? FontWeight.bold : FontWeight.normal)),
      subtitle: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text(detail(context, a), key: const Key('alert-detail')),
        Text('${a.homeName} · ${context.formatDate(a.lastAt)}'),
        if (a.occurrences > 1) Text(l10n.occurrences(a.occurrences)),
        if (a.resolvedAt != null) Text(l10n.resolved, key: const Key('alert-resolved')),
      ]),
      trailing: a.unread
          ? IconButton(
              key: const Key('alert-read'),
              tooltip: l10n.markRead,
              icon: const Icon(Icons.mark_email_read_outlined),
              onPressed: () => onRead(a),
            )
          : null,
      onTap: () async {
        await onRead(a);
        if (context.mounted) {
          context.push('/homes/${a.homeId}');
        }
      },
    );
  }
}
