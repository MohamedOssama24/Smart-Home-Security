import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';

import '../core/api/shsc_api.dart';
import '../l10n/app_localizations.dart';

extension L10nContext on BuildContext {
  AppLocalizations get l10n => AppLocalizations.of(this);

  String formatDate(DateTime? d) =>
      d == null ? '-' : DateFormat.yMd(Localizations.localeOf(this).languageCode).add_Hm().format(d);
}

String errorText(BuildContext context, Object error) {
  if (error is ApiException && error.offline) {
    return context.l10n.networkError;
  }
  return context.l10n.genericError;
}

/// Loading / error (with retry) / data of an async provider.
class AsyncBody<T> extends StatelessWidget {
  const AsyncBody({super.key, required this.value, required this.data, required this.onRetry});

  final AsyncValue<T> value;
  final Widget Function(T data) data;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) {
    return value.when(
      skipLoadingOnRefresh: true,
      data: data,
      loading: () => const Center(child: CircularProgressIndicator()),
      error: (e, _) => Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            Text(errorText(context, e), key: const Key('error'), textAlign: TextAlign.center),
            const SizedBox(height: 12),
            OutlinedButton(onPressed: onRetry, child: Text(context.l10n.retry)),
          ]),
        ),
      ),
    );
  }
}

/// Colours shared by severities and risk levels (text always accompanies the colour).
Color severityColor(String? severity) => switch (severity) {
      'CRITICAL' => const Color(0xFFB3261E),
      'HIGH' => const Color(0xFFE8710A),
      'MEDIUM' => const Color(0xFFC79100),
      'LOW' => const Color(0xFF1E8E3E),
      _ => const Color(0xFF5F6368),
    };

class SeverityChip extends StatelessWidget {
  const SeverityChip(this.label, this.severity, {super.key});

  final String label;
  final String? severity;

  @override
  Widget build(BuildContext context) {
    final color = severityColor(severity);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color),
      ),
      child: Text(label, style: TextStyle(color: color, fontWeight: FontWeight.w600, fontSize: 12)),
    );
  }
}
