import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../core/api/models.dart';
import '../core/api/shsc_api.dart';
import '../core/providers.dart';
import 'common.dart';

/// Scan history of the home and the manual scan request (the backend queues it for the home's
/// agent: the phone itself never scans anything).
class ScansPage extends ConsumerWidget {
  const ScansPage({super.key, required this.homeId});

  final String homeId;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = context.l10n;
    final scans = ref.watch(scansProvider(homeId));
    return Scaffold(
      appBar: AppBar(title: Text(l10n.scans)),
      floatingActionButton: ref.watch(canProvider('scan:create'))
          ? FloatingActionButton.extended(
              key: const Key('new-scan'),
              onPressed: () => _request(context, ref),
              icon: const Icon(Icons.radar),
              label: Text(l10n.newScan),
            )
          : null,
      body: RefreshIndicator(
        onRefresh: () => ref.refresh(scansProvider(homeId).future),
        child: AsyncBody(
          value: scans,
          onRetry: () => ref.invalidate(scansProvider(homeId)),
          data: (list) => list.isEmpty
              ? ListView(children: [Padding(padding: const EdgeInsets.all(24), child: Text(l10n.noScans))])
              : ListView.separated(
                  padding: const EdgeInsets.only(bottom: 88),
                  itemCount: list.length,
                  separatorBuilder: (_, _) => const Divider(height: 1),
                  itemBuilder: (_, i) => ScanTile(scan: list[i]),
                ),
        ),
      ),
    );
  }

  Future<void> _request(BuildContext context, WidgetRef ref) async {
    final profile = await showDialog<String>(context: context, builder: (_) => const ScanRequestDialog());
    if (profile == null || !context.mounted) {
      return;
    }
    final l10n = context.l10n;
    try {
      final scan = await ref.read(apiProvider).requestScan(homeId, profile);
      ref.invalidate(scansProvider(homeId));
      if (context.mounted) {
        context.push('/scans/${scan.id}');
      }
    } on ApiException catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(
          key: const Key('scan-error'),
          content: Text(e.offline ? l10n.networkError : l10n.scanError(e.code ?? '')),
        ));
      }
    }
  }
}

class ScanTile extends StatelessWidget {
  const ScanTile({super.key, required this.scan});

  final Scan scan;

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    return ListTile(
      key: Key('scan-${scan.id}'),
      leading: Icon(scan.active ? Icons.hourglass_top : Icons.radar),
      title: Text('${l10n.scanProfile(scan.profile)} · ${l10n.scanStatus(scan.status)}'),
      subtitle: Text('${context.formatDate(scan.requestedAt)} · ${l10n.scanDevices(scan.devicesDiscovered)}'),
      onTap: () => context.push('/scans/${scan.id}'),
    );
  }
}

/// Choice of the profile, with the reminder of what the scan does and does not do.
class ScanRequestDialog extends StatefulWidget {
  const ScanRequestDialog({super.key});

  @override
  State<ScanRequestDialog> createState() => _ScanRequestDialogState();
}

class _ScanRequestDialogState extends State<ScanRequestDialog> {
  static const profiles = ['DISCOVERY', 'QUICK', 'STANDARD'];
  String _profile = 'STANDARD';

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    return AlertDialog(
      title: Text(l10n.newScan),
      content: SingleChildScrollView(
        child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
          Wrap(spacing: 8, children: [
            for (final p in profiles)
              ChoiceChip(
                key: Key('profile-$p'),
                label: Text(l10n.scanProfile(p)),
                selected: _profile == p,
                onSelected: (_) => setState(() => _profile = p),
              ),
          ]),
          const SizedBox(height: 8),
          Text(l10n.scanProfileHelp(_profile)),
          const SizedBox(height: 12),
          Text(l10n.scanConfirm, style: Theme.of(context).textTheme.bodySmall),
        ]),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: Text(l10n.cancel)),
        FilledButton(
          key: const Key('start-scan'),
          onPressed: () => Navigator.pop(context, _profile),
          child: Text(l10n.start),
        ),
      ],
    );
  }
}
