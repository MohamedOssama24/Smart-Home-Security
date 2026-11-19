import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../core/api/models.dart';
import '../core/api/shsc_api.dart';
import '../core/providers.dart';
import 'common.dart';

/// How often an active scan is refreshed (overridden in tests).
final scanPollIntervalProvider = Provider<Duration>((ref) => const Duration(seconds: 3));

/// One scan: status and progress, refreshed until it ends; cancellation while active.
class ScanPage extends ConsumerStatefulWidget {
  const ScanPage({super.key, required this.scanId});

  final String scanId;

  @override
  ConsumerState<ScanPage> createState() => _ScanPageState();
}

class _ScanPageState extends ConsumerState<ScanPage> {
  Scan? _scan;
  Object? _error;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _load() async {
    try {
      final scan = await ref.read(apiProvider).scan(widget.scanId);
      if (!mounted) {
        return;
      }
      setState(() {
        _scan = scan;
        _error = null;
      });
      if (scan.active) {
        _timer = Timer(ref.read(scanPollIntervalProvider), _load);
      } else {
        ref.invalidate(scansProvider(scan.homeId));
        ref.invalidate(overviewProvider);
      }
    } on ApiException catch (e) {
      if (mounted) {
        setState(() => _error = e);
      }
    }
  }

  Future<void> _cancel() async {
    try {
      final scan = await ref.read(apiProvider).cancelScan(widget.scanId);
      if (mounted) {
        setState(() => _scan = scan);
      }
    } on ApiException catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(errorText(context, e))));
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    final s = _scan;
    return Scaffold(
      appBar: AppBar(title: Text(l10n.scans)),
      body: s == null
          ? AsyncBody<void>(
              value: _error == null ? const AsyncLoading() : AsyncError(_error!, StackTrace.empty),
              onRetry: _load,
              data: (_) => const SizedBox.shrink(),
            )
          : ListView(padding: const EdgeInsets.all(16), children: [
              Text(l10n.scanProfile(s.profile), style: Theme.of(context).textTheme.titleMedium),
              const SizedBox(height: 4),
              Text(l10n.scanStatus(s.status), key: const Key('scan-status'),
                  style: Theme.of(context).textTheme.headlineSmall),
              const SizedBox(height: 12),
              if (s.active) ...[
                LinearProgressIndicator(value: s.percent == null ? null : s.percent! / 100),
                if (s.percent != null) Text(l10n.scanProgress(s.percent!)),
                if (s.cancelRequestedAt != null) Text(l10n.scanCancelRequested),
              ],
              const SizedBox(height: 8),
              Text(l10n.scanDevices(s.devicesDiscovered), key: const Key('scan-devices')),
              Text(context.formatDate(s.requestedAt)),
              if (s.failureReason != null) Text(l10n.scanFailure(s.failureReason!)),
              for (final w in s.warnings) Text('⚠ $w'),
              const SizedBox(height: 16),
              if (s.active && s.cancelRequestedAt == null && ref.watch(canProvider('scan:create')))
                OutlinedButton(key: const Key('stop-scan'), onPressed: _cancel, child: Text(l10n.stopScan)),
              if (!s.active && ref.watch(canProvider('device:read')))
                FilledButton.tonal(
                  key: const Key('scan-open-devices'),
                  onPressed: () => context.push('/homes/${s.homeId}/devices'),
                  child: Text(l10n.viewDevices),
                ),
            ]),
    );
  }
}
