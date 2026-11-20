import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../core/api/models.dart';
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
          return ListView(
            children: [
              ListTile(
                leading: Icon(categoryIcon(d.category), size: 36),
                title: Text(l10n.category(d.category), key: const Key('device-category')),
                subtitle: Text('${l10n.deviceConfidence}: ${l10n.confidence(d.confidence)}'),
              ),
              row(l10n.deviceIp, d.ip),
              row(l10n.deviceMac, d.mac),
              if (d.macRandomized) ListTile(dense: true, title: Text(l10n.randomizedMac)),
              if (d.identity.isEmpty) ...[
                row(l10n.deviceManufacturer, d.manufacturer),
                row(l10n.deviceModel, d.model),
                row(l10n.deviceOs, d.os),
              ],
              row(l10n.deviceLastSeen, context.formatDate(d.lastSeenAt)),
              // M20: device card, every field with its status and sources (read-only in the app)
              if (d.identity.isNotEmpty) ...[
                const Divider(),
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
                  child: Text(l10n.identityTitle, style: Theme.of(context).textTheme.titleMedium),
                ),
                if (d.customName != null) row(l10n.identityCustomName, d.customName),
                for (final f in d.identity)
                  ListTile(
                    key: Key('identity-${f.field}'),
                    dense: true,
                    title: Text(l10n.identityField(f.field)),
                    subtitle: Text(
                      [
                        f.value ?? '—',
                        if (f.userConfirmed) l10n.identityUserConfirmed,
                        if (!f.userConfirmed && f.sources.isNotEmpty)
                          '${l10n.identitySources}: ${f.sources.join(', ')}',
                        if (f.conflict) l10n.identityConflict,
                      ].join(' · '),
                    ),
                    trailing: Chip(
                      key: Key('identity-status-${f.field}'),
                      label: Text(l10n.identityStatus(f.status)),
                      visualDensity: VisualDensity.compact,
                      avatar: Icon(switch (f.status) {
                        'VERIFIED' => Icons.verified,
                        'PROBABLE' => Icons.help_outline,
                        _ => Icons.remove,
                      }, size: 16),
                    ),
                  ),
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
                  child: Text(l10n.identityStatusRule, style: Theme.of(context).textTheme.bodySmall),
                ),
              ],
              // M24: people associated with the device (read-only in the app)
              if (ref.watch(canProvider('person:read'))) _People(homeId: d.homeId, deviceId: d.id),
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
              if (d.interfaces.isNotEmpty) ...[
                const Divider(),
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
                  child: Text(l10n.deviceInterfaces, style: Theme.of(context).textTheme.titleMedium),
                ),
                for (final i in d.interfaces)
                  ListTile(
                    key: Key('interface-${i.mac}'),
                    dense: true,
                    title: SelectableText(i.mac),
                    subtitle: Text(
                      [
                        if (i.vendor != null) i.vendor!,
                        if (i.agentInterface != null) i.agentInterface!,
                        if (i.macRandomized) l10n.randomizedMac,
                        if (!i.current) l10n.addressPast,
                      ].join(' · '),
                    ),
                  ),
              ],
              if (d.addressHistory.isNotEmpty) ...[
                const Divider(),
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
                  child: Text(l10n.deviceAddresses, style: Theme.of(context).textTheme.titleMedium),
                ),
                for (final a in d.addressHistory)
                  ListTile(
                    key: Key('address-${a.address}'),
                    dense: true,
                    title: SelectableText(a.address),
                    subtitle: Text(
                      [
                        'IPv${a.family}',
                        if (a.scope != null) l10n.addressScope(a.scope!),
                        if (a.interfaceId != null) l10n.addressInterfaceId(a.interfaceId!),
                        a.current ? l10n.addressCurrent : l10n.addressPast,
                      ].join(' · '),
                    ),
                  ),
              ],
              if (d.identificationHistory.isNotEmpty) ...[
                const Divider(),
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
                  child: Text(l10n.identityHistory, style: Theme.of(context).textTheme.titleMedium),
                ),
                for (final (i, c) in d.identificationHistory.indexed)
                  ListTile(
                    key: Key('identity-change-$i'),
                    dense: true,
                    title: Text('${l10n.identityField(c.field)}: ${c.oldValue ?? '—'} → ${c.newValue ?? '—'}'),
                    subtitle: Text(
                      [
                        if (c.newStatus != null) l10n.identityStatus(c.newStatus!),
                        l10n.identityOrigin(c.origin),
                        if (c.changedAt != null) context.formatDate(c.changedAt),
                      ].join(' · '),
                    ),
                  ),
              ],
            ],
          );
        },
      ),
    );
  }
}

class _People extends ConsumerWidget {
  const _People({required this.homeId, required this.deviceId});

  final String homeId;
  final String deviceId;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = context.l10n;
    final people =
        ref.watch(devicePeopleProvider(homeId)).value?.where((p) => p.deviceId == deviceId).toList() ??
        const <DevicePerson>[];
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Divider(),
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
          child: Text(l10n.peopleTitle, style: Theme.of(context).textTheme.titleMedium),
        ),
        if (people.isEmpty)
          Padding(
            padding: const EdgeInsets.all(16),
            child: Text(l10n.peopleNone, key: const Key('people-none')),
          )
        else
          for (final p in people)
            ListTile(
              key: Key('person-${p.personId}'),
              dense: true,
              leading: const Icon(Icons.person_outline),
              title: Text(p.name),
              subtitle: Text([l10n.personSource(p.source), if (p.evidence != null) p.evidence!].join(' · ')),
              trailing: Chip(label: Text(l10n.personStatus(p.status)), visualDensity: VisualDensity.compact),
            ),
      ],
    );
  }
}
