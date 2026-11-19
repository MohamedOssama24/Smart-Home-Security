import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../core/providers.dart';
import 'common.dart';
import 'devices_page.dart';

/// Identification of one device and the services seen by the last port scan.
class DevicePage extends ConsumerWidget {
  const DevicePage({super.key, required this.deviceId});

  final String deviceId;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = context.l10n;
    final device = ref.watch(deviceProvider(deviceId));
    return Scaffold(
      appBar: AppBar(title: Text(device.value?.name ?? l10n.devices)),
      body: AsyncBody(
        value: device,
        onRetry: () => ref.invalidate(deviceProvider(deviceId)),
        data: (d) {
          Widget row(String label, String? value) => value == null || value.isEmpty
              ? const SizedBox.shrink()
              : ListTile(dense: true, title: Text(label), subtitle: SelectableText(value));
          return ListView(children: [
            ListTile(
              leading: Icon(categoryIcon(d.category), size: 36),
              title: Text(l10n.category(d.category), key: const Key('device-category')),
              subtitle: Text('${l10n.deviceConfidence}: ${l10n.confidence(d.confidence)}'),
            ),
            row(l10n.deviceIp, d.ip),
            row(l10n.deviceMac, d.mac),
            if (d.macRandomized) ListTile(dense: true, title: Text(l10n.randomizedMac)),
            row(l10n.deviceManufacturer, d.manufacturer),
            row(l10n.deviceModel, d.model),
            row(l10n.deviceOs, d.os),
            row(l10n.deviceLastSeen, context.formatDate(d.lastSeenAt)),
            const Divider(),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
              child: Text(l10n.openPorts, style: Theme.of(context).textTheme.titleMedium),
            ),
            if (d.ports.isEmpty)
              Padding(padding: const EdgeInsets.all(16), child: Text(l10n.noOpenPorts))
            else
              for (final p in d.ports)
                ListTile(
                  key: Key('port-${p.protocol}-${p.port}'),
                  dense: true,
                  leading: Text('${p.port}/${p.protocol.toLowerCase()}'),
                  title: Text(p.service ?? '?'),
                  subtitle: p.product == null ? null : Text([p.product, p.version].whereType<String>().join(' ')),
                ),
          ]);
        },
      ),
    );
  }
}
