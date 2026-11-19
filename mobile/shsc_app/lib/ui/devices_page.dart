import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../core/providers.dart';
import 'common.dart';

IconData categoryIcon(String category) => switch (category) {
      'ROUTER' => Icons.router,
      'IP_CAMERA' => Icons.videocam,
      'SMART_TV' => Icons.tv,
      'SMARTPHONE' => Icons.smartphone,
      'TABLET' => Icons.tablet,
      'LAPTOP' => Icons.laptop,
      'DESKTOP' => Icons.desktop_windows,
      'PRINTER' => Icons.print,
      'NAS' => Icons.storage,
      'SMART_PLUG' => Icons.power,
      'SMART_SPEAKER' => Icons.speaker,
      'IOT' => Icons.sensors,
      _ => Icons.device_unknown,
    };

/// Devices of the home (inventory built by the scans).
class DevicesPage extends ConsumerWidget {
  const DevicesPage({super.key, required this.homeId});

  final String homeId;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = context.l10n;
    final devices = ref.watch(devicesProvider(homeId));
    return Scaffold(
      appBar: AppBar(title: Text(l10n.devices)),
      body: RefreshIndicator(
        onRefresh: () => ref.refresh(devicesProvider(homeId).future),
        child: AsyncBody(
          value: devices,
          onRetry: () => ref.invalidate(devicesProvider(homeId)),
          data: (list) => list.isEmpty
              ? ListView(children: [Padding(padding: const EdgeInsets.all(24), child: Text(l10n.noDevices))])
              : ListView.separated(
                  itemCount: list.length,
                  separatorBuilder: (_, _) => const Divider(height: 1),
                  itemBuilder: (_, i) {
                    final d = list[i];
                    return ListTile(
                      key: Key('device-${d.id}'),
                      leading: Icon(categoryIcon(d.category)),
                      title: Text(d.name),
                      subtitle: Text([l10n.category(d.category), if (d.ip != null) d.ip!].join(' · ')),
                      trailing: d.ports.isEmpty ? null : Text('${d.ports.length}'),
                      onTap: () => context.push('/devices/${d.id}'),
                    );
                  },
                ),
        ),
      ),
    );
  }
}
