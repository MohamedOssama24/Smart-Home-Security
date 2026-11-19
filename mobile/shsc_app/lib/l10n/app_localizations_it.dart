// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for Italian (`it`).
class AppLocalizationsIt extends AppLocalizations {
  AppLocalizationsIt([String locale = 'it']) : super(locale);

  @override
  String get appTitle => 'Smart Home Security Check';

  @override
  String get loginTitle => 'Accedi';

  @override
  String get email => 'Email';

  @override
  String get password => 'Password';

  @override
  String get signIn => 'Accedi';

  @override
  String get loginInvalid => 'Email o password non corretti.';

  @override
  String get loginLocked => 'Troppi tentativi. Riprova tra qualche minuto.';

  @override
  String get networkError =>
      'Impossibile contattare il server. Controlla la connessione.';

  @override
  String get genericError => 'Si è verificato un errore. Riprova.';

  @override
  String get sessionExpired => 'La sessione è scaduta: accedi di nuovo.';

  @override
  String get fieldRequired => 'Campo obbligatorio';

  @override
  String get retry => 'Riprova';

  @override
  String get logout => 'Esci';

  @override
  String get homes => 'Abitazioni';

  @override
  String get noHomes => 'Nessuna abitazione. Aggiungila dalla dashboard web.';

  @override
  String get alerts => 'Avvisi';

  @override
  String get score => 'Punteggio di sicurezza';

  @override
  String scoreValue(int score) {
    return '$score/100';
  }

  @override
  String scoreChange(int change) {
    String _temp0 = intl.Intl.pluralLogic(
      change,
      locale: localeName,
      other: '$change punti dall\'ultima volta',
      zero: 'invariato',
    );
    return '$_temp0';
  }

  @override
  String get notComputed => 'Punteggio non calcolato';

  @override
  String get notComputedDiscovery =>
      'Serve una scansione Rapida o Standard per calcolarlo.';

  @override
  String get provisional => 'Provvisorio: copertura dell\'analisi bassa';

  @override
  String openFindings(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count problemi aperti',
      one: '1 problema aperto',
      zero: 'Nessun problema aperto',
    );
    return '$_temp0';
  }

  @override
  String kevFindings(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count vulnerabilità sfruttate attivamente',
      one: '1 vulnerabilità sfruttata attivamente',
    );
    return '$_temp0';
  }

  @override
  String devicesCount(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count dispositivi',
      one: '1 dispositivo',
      zero: 'Nessun dispositivo',
    );
    return '$_temp0';
  }

  @override
  String lastScan(String date) {
    return 'Ultima scansione: $date';
  }

  @override
  String get neverScanned => 'Nessuna scansione completata';

  @override
  String get noSecurityAccess =>
      'Il tuo ruolo non permette di vedere i dati di sicurezza.';

  @override
  String riskLevel(String level) {
    String _temp0 = intl.Intl.selectLogic(level, {
      'LOW': 'Rischio basso',
      'MEDIUM': 'Rischio medio',
      'HIGH': 'Rischio alto',
      'CRITICAL': 'Rischio critico',
      'other': '-',
    });
    return '$_temp0';
  }

  @override
  String severity(String severity) {
    String _temp0 = intl.Intl.selectLogic(severity, {
      'CRITICAL': 'Critica',
      'HIGH': 'Alta',
      'MEDIUM': 'Media',
      'LOW': 'Bassa',
      'INFO': 'Informativa',
      'INFORMATIONAL': 'Informativa',
      'other': '-',
    });
    return '$_temp0';
  }

  @override
  String get devices => 'Dispositivi';

  @override
  String get noDevices => 'Nessun dispositivo trovato. Avvia una scansione.';

  @override
  String get deviceIp => 'Indirizzo IP';

  @override
  String get deviceMac => 'Indirizzo MAC';

  @override
  String get deviceManufacturer => 'Produttore';

  @override
  String get deviceModel => 'Modello';

  @override
  String get deviceOs => 'Sistema operativo';

  @override
  String get deviceCategory => 'Tipo';

  @override
  String get deviceConfidence => 'Affidabilità';

  @override
  String get deviceLastSeen => 'Visto l\'ultima volta';

  @override
  String get randomizedMac => 'MAC casuale (privacy del dispositivo)';

  @override
  String get openPorts => 'Servizi esposti in rete';

  @override
  String get noOpenPorts =>
      'Nessuna porta aperta rilevata dall\'ultima scansione delle porte.';

  @override
  String confidence(String level) {
    String _temp0 = intl.Intl.selectLogic(level, {
      'HIGH': 'Alta',
      'MEDIUM': 'Media',
      'LOW': 'Bassa',
      'other': '-',
    });
    return '$_temp0';
  }

  @override
  String category(String category) {
    String _temp0 = intl.Intl.selectLogic(category, {
      'ROUTER': 'Router',
      'IP_CAMERA': 'Videocamera',
      'SMART_TV': 'Smart TV',
      'SMARTPHONE': 'Smartphone',
      'TABLET': 'Tablet',
      'LAPTOP': 'Portatile',
      'DESKTOP': 'Computer',
      'PRINTER': 'Stampante',
      'NAS': 'NAS',
      'SMART_PLUG': 'Presa smart',
      'SMART_SPEAKER': 'Altoparlante smart',
      'IOT': 'Dispositivo IoT',
      'other': 'Non identificato',
    });
    return '$_temp0';
  }

  @override
  String get scans => 'Scansioni';

  @override
  String get noScans => 'Nessuna scansione.';

  @override
  String get newScan => 'Nuova scansione';

  @override
  String scanProfile(String profile) {
    String _temp0 = intl.Intl.selectLogic(profile, {
      'DISCOVERY': 'Rilevamento',
      'QUICK': 'Rapida',
      'STANDARD': 'Standard',
      'other': '$profile',
    });
    return '$_temp0';
  }

  @override
  String scanProfileHelp(String profile) {
    String _temp0 = intl.Intl.selectLogic(profile, {
      'DISCOVERY': 'Trova i dispositivi in rete, senza controllare i servizi.',
      'QUICK': 'Dispositivi e porte più comuni: pochi minuti.',
      'STANDARD': 'Dispositivi, porte e servizi: analisi completa.',
      'other': '',
    });
    return '$_temp0';
  }

  @override
  String get scanConfirm =>
      'La scansione è eseguita dall\'agent installato in casa, solo sulle reti che hai autorizzato e senza tentativi di accesso ai dispositivi.';

  @override
  String get start => 'Avvia';

  @override
  String get cancel => 'Annulla';

  @override
  String get stopScan => 'Interrompi';

  @override
  String scanStatus(String status) {
    String _temp0 = intl.Intl.selectLogic(status, {
      'PENDING': 'In attesa',
      'QUEUED': 'In coda',
      'RUNNING': 'In corso',
      'COMPLETED': 'Completata',
      'COMPLETED_WITH_WARNINGS': 'Completata con avvisi',
      'FAILED': 'Non riuscita',
      'CANCELLED': 'Annullata',
      'other': '$status',
    });
    return '$_temp0';
  }

  @override
  String scanProgress(int percent) {
    return '$percent%';
  }

  @override
  String scanDevices(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count dispositivi trovati',
      one: '1 dispositivo trovato',
      zero: 'Nessun dispositivo trovato',
    );
    return '$_temp0';
  }

  @override
  String scanFailure(String reason) {
    return 'Motivo: $reason';
  }

  @override
  String get scanCancelRequested => 'Annullamento richiesto';

  @override
  String scanError(String code) {
    String _temp0 = intl.Intl.selectLogic(code, {
      'NO_AUTHORIZED_NETWORK':
          'Nessuna rete autorizzata: autorizzala dalla dashboard web.',
      'AGENT_OFFLINE': 'L\'agent dell\'abitazione non è raggiungibile.',
      'SCAN_ALREADY_ACTIVE': 'C\'è già una scansione in corso.',
      'PROFILE_NOT_AVAILABLE': 'Profilo non disponibile per questo agent.',
      'other': 'Impossibile avviare la scansione.',
    });
    return '$_temp0';
  }

  @override
  String alertTitle(String type) {
    String _temp0 = intl.Intl.selectLogic(type, {
      'NEW_FINDING': 'Nuovo problema di sicurezza',
      'FINDING_RESOLVED': 'Problema risolto',
      'SCORE_DROPPED': 'Il punteggio è sceso',
      'NEW_DEVICE': 'Nuovo dispositivo in rete',
      'SCAN_FAILED': 'Scansione non riuscita',
      'AGENT_OFFLINE': 'Agent non raggiungibile',
      'other': 'Avviso',
    });
    return '$_temp0';
  }

  @override
  String alertScore(int score, int change) {
    return 'Ora $score/100 ($change punti)';
  }

  @override
  String alertDevices(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count dispositivi nuovi',
      one: '1 dispositivo nuovo',
    );
    return '$_temp0';
  }

  @override
  String alertAgent(String name) {
    return 'Agent \"$name\" senza contatto da più di 15 minuti';
  }

  @override
  String occurrences(int count) {
    return 'Ripetuto $count volte';
  }

  @override
  String get resolved => 'Risolto';

  @override
  String get markRead => 'Segna come letto';

  @override
  String get markAllRead => 'Segna tutti come letti';

  @override
  String get unreadOnly => 'Solo da leggere';

  @override
  String get noAlerts => 'Nessun avviso.';

  @override
  String get pushDisabled => 'Notifiche push non configurate in questa build.';

  @override
  String get viewDevices => 'Dispositivi';

  @override
  String get viewScans => 'Scansioni';
}
