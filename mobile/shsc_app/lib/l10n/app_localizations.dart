import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:intl/intl.dart' as intl;

import 'app_localizations_en.dart';
import 'app_localizations_it.dart';

// ignore_for_file: type=lint

/// Callers can lookup localized strings with an instance of AppLocalizations
/// returned by `AppLocalizations.of(context)`.
///
/// Applications need to include `AppLocalizations.delegate()` in their app's
/// `localizationDelegates` list, and the locales they support in the app's
/// `supportedLocales` list. For example:
///
/// ```dart
/// import 'l10n/app_localizations.dart';
///
/// return MaterialApp(
///   localizationsDelegates: AppLocalizations.localizationsDelegates,
///   supportedLocales: AppLocalizations.supportedLocales,
///   home: MyApplicationHome(),
/// );
/// ```
///
/// ## Update pubspec.yaml
///
/// Please make sure to update your pubspec.yaml to include the following
/// packages:
///
/// ```yaml
/// dependencies:
///   # Internationalization support.
///   flutter_localizations:
///     sdk: flutter
///   intl: any # Use the pinned version from flutter_localizations
///
///   # Rest of dependencies
/// ```
///
/// ## iOS Applications
///
/// iOS applications define key application metadata, including supported
/// locales, in an Info.plist file that is built into the application bundle.
/// To configure the locales supported by your app, you’ll need to edit this
/// file.
///
/// First, open your project’s ios/Runner.xcworkspace Xcode workspace file.
/// Then, in the Project Navigator, open the Info.plist file under the Runner
/// project’s Runner folder.
///
/// Next, select the Information Property List item, select Add Item from the
/// Editor menu, then select Localizations from the pop-up menu.
///
/// Select and expand the newly-created Localizations item then, for each
/// locale your application supports, add a new item and select the locale
/// you wish to add from the pop-up menu in the Value field. This list should
/// be consistent with the languages listed in the AppLocalizations.supportedLocales
/// property.
abstract class AppLocalizations {
  AppLocalizations(String locale)
    : localeName = intl.Intl.canonicalizedLocale(locale.toString());

  final String localeName;

  static AppLocalizations of(BuildContext context) {
    return Localizations.of<AppLocalizations>(context, AppLocalizations)!;
  }

  static const LocalizationsDelegate<AppLocalizations> delegate =
      _AppLocalizationsDelegate();

  /// A list of this localizations delegate along with the default localizations
  /// delegates.
  ///
  /// Returns a list of localizations delegates containing this delegate along with
  /// GlobalMaterialLocalizations.delegate, GlobalCupertinoLocalizations.delegate,
  /// and GlobalWidgetsLocalizations.delegate.
  ///
  /// Additional delegates can be added by appending to this list in
  /// MaterialApp. This list does not have to be used at all if a custom list
  /// of delegates is preferred or required.
  static const List<LocalizationsDelegate<dynamic>> localizationsDelegates =
      <LocalizationsDelegate<dynamic>>[
        delegate,
        GlobalMaterialLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
      ];

  /// A list of this localizations delegate's supported locales.
  static const List<Locale> supportedLocales = <Locale>[
    Locale('en'),
    Locale('it'),
  ];

  /// No description provided for @appTitle.
  ///
  /// In it, this message translates to:
  /// **'Smart Home Security Check'**
  String get appTitle;

  /// No description provided for @loginTitle.
  ///
  /// In it, this message translates to:
  /// **'Accedi'**
  String get loginTitle;

  /// No description provided for @email.
  ///
  /// In it, this message translates to:
  /// **'Email'**
  String get email;

  /// No description provided for @password.
  ///
  /// In it, this message translates to:
  /// **'Password'**
  String get password;

  /// No description provided for @signIn.
  ///
  /// In it, this message translates to:
  /// **'Accedi'**
  String get signIn;

  /// No description provided for @loginInvalid.
  ///
  /// In it, this message translates to:
  /// **'Email o password non corretti.'**
  String get loginInvalid;

  /// No description provided for @loginLocked.
  ///
  /// In it, this message translates to:
  /// **'Troppi tentativi. Riprova tra qualche minuto.'**
  String get loginLocked;

  /// No description provided for @networkError.
  ///
  /// In it, this message translates to:
  /// **'Impossibile contattare il server. Controlla la connessione.'**
  String get networkError;

  /// No description provided for @genericError.
  ///
  /// In it, this message translates to:
  /// **'Si è verificato un errore. Riprova.'**
  String get genericError;

  /// No description provided for @sessionExpired.
  ///
  /// In it, this message translates to:
  /// **'La sessione è scaduta: accedi di nuovo.'**
  String get sessionExpired;

  /// No description provided for @fieldRequired.
  ///
  /// In it, this message translates to:
  /// **'Campo obbligatorio'**
  String get fieldRequired;

  /// No description provided for @retry.
  ///
  /// In it, this message translates to:
  /// **'Riprova'**
  String get retry;

  /// No description provided for @logout.
  ///
  /// In it, this message translates to:
  /// **'Esci'**
  String get logout;

  /// No description provided for @homes.
  ///
  /// In it, this message translates to:
  /// **'Abitazioni'**
  String get homes;

  /// No description provided for @noHomes.
  ///
  /// In it, this message translates to:
  /// **'Nessuna abitazione. Aggiungila dalla dashboard web.'**
  String get noHomes;

  /// No description provided for @alerts.
  ///
  /// In it, this message translates to:
  /// **'Avvisi'**
  String get alerts;

  /// No description provided for @score.
  ///
  /// In it, this message translates to:
  /// **'Punteggio di sicurezza'**
  String get score;

  /// No description provided for @scoreValue.
  ///
  /// In it, this message translates to:
  /// **'{score}/100'**
  String scoreValue(int score);

  /// No description provided for @scoreChange.
  ///
  /// In it, this message translates to:
  /// **'{change, plural, =0{invariato} other{{change} punti dall\'ultima volta}}'**
  String scoreChange(int change);

  /// No description provided for @notComputed.
  ///
  /// In it, this message translates to:
  /// **'Punteggio non calcolato'**
  String get notComputed;

  /// No description provided for @notComputedDiscovery.
  ///
  /// In it, this message translates to:
  /// **'Serve una scansione Rapida o Standard per calcolarlo.'**
  String get notComputedDiscovery;

  /// No description provided for @provisional.
  ///
  /// In it, this message translates to:
  /// **'Provvisorio: copertura dell\'analisi bassa'**
  String get provisional;

  /// No description provided for @openFindings.
  ///
  /// In it, this message translates to:
  /// **'{count, plural, =0{Nessun problema aperto} =1{1 problema aperto} other{{count} problemi aperti}}'**
  String openFindings(int count);

  /// No description provided for @kevFindings.
  ///
  /// In it, this message translates to:
  /// **'{count, plural, =1{1 vulnerabilità sfruttata attivamente} other{{count} vulnerabilità sfruttate attivamente}}'**
  String kevFindings(int count);

  /// No description provided for @devicesCount.
  ///
  /// In it, this message translates to:
  /// **'{count, plural, =0{Nessun dispositivo} =1{1 dispositivo} other{{count} dispositivi}}'**
  String devicesCount(int count);

  /// No description provided for @lastScan.
  ///
  /// In it, this message translates to:
  /// **'Ultima scansione: {date}'**
  String lastScan(String date);

  /// No description provided for @neverScanned.
  ///
  /// In it, this message translates to:
  /// **'Nessuna scansione completata'**
  String get neverScanned;

  /// No description provided for @noSecurityAccess.
  ///
  /// In it, this message translates to:
  /// **'Il tuo ruolo non permette di vedere i dati di sicurezza.'**
  String get noSecurityAccess;

  /// No description provided for @riskLevel.
  ///
  /// In it, this message translates to:
  /// **'{level, select, LOW{Rischio basso} MEDIUM{Rischio medio} HIGH{Rischio alto} CRITICAL{Rischio critico} other{-}}'**
  String riskLevel(String level);

  /// No description provided for @severity.
  ///
  /// In it, this message translates to:
  /// **'{severity, select, CRITICAL{Critica} HIGH{Alta} MEDIUM{Media} LOW{Bassa} INFO{Informativa} INFORMATIONAL{Informativa} other{-}}'**
  String severity(String severity);

  /// No description provided for @devices.
  ///
  /// In it, this message translates to:
  /// **'Dispositivi'**
  String get devices;

  /// No description provided for @noDevices.
  ///
  /// In it, this message translates to:
  /// **'Nessun dispositivo trovato. Avvia una scansione.'**
  String get noDevices;

  /// No description provided for @deviceIp.
  ///
  /// In it, this message translates to:
  /// **'Indirizzo IP'**
  String get deviceIp;

  /// No description provided for @deviceMac.
  ///
  /// In it, this message translates to:
  /// **'Indirizzo MAC'**
  String get deviceMac;

  /// No description provided for @deviceManufacturer.
  ///
  /// In it, this message translates to:
  /// **'Produttore'**
  String get deviceManufacturer;

  /// No description provided for @deviceModel.
  ///
  /// In it, this message translates to:
  /// **'Modello'**
  String get deviceModel;

  /// No description provided for @deviceOs.
  ///
  /// In it, this message translates to:
  /// **'Sistema operativo'**
  String get deviceOs;

  /// No description provided for @deviceCategory.
  ///
  /// In it, this message translates to:
  /// **'Tipo'**
  String get deviceCategory;

  /// No description provided for @deviceConfidence.
  ///
  /// In it, this message translates to:
  /// **'Affidabilità'**
  String get deviceConfidence;

  /// No description provided for @deviceLastSeen.
  ///
  /// In it, this message translates to:
  /// **'Visto l\'ultima volta'**
  String get deviceLastSeen;

  /// No description provided for @randomizedMac.
  ///
  /// In it, this message translates to:
  /// **'MAC casuale (privacy del dispositivo)'**
  String get randomizedMac;

  /// No description provided for @deviceInterfaces.
  ///
  /// In it, this message translates to:
  /// **'Interfacce di rete'**
  String get deviceInterfaces;

  /// No description provided for @deviceAddresses.
  ///
  /// In it, this message translates to:
  /// **'Indirizzi IP e storico'**
  String get deviceAddresses;

  /// No description provided for @addressCurrent.
  ///
  /// In it, this message translates to:
  /// **'attuale'**
  String get addressCurrent;

  /// No description provided for @addressPast.
  ///
  /// In it, this message translates to:
  /// **'non più visto'**
  String get addressPast;

  /// No description provided for @addressScope.
  ///
  /// In it, this message translates to:
  /// **'{scope, select, PRIVATE{privato} PUBLIC{pubblico} LINK_LOCAL{link-local} LOOPBACK{loopback} UNIQUE_LOCAL{locale univoco (ULA)} GLOBAL{globale} MULTICAST{multicast} other{altro}}'**
  String addressScope(String scope);

  /// No description provided for @addressInterfaceId.
  ///
  /// In it, this message translates to:
  /// **'{kind, select, EUI64{derivato dal MAC (EUI-64)} RANDOM{casuale (privacy)} other{-}}'**
  String addressInterfaceId(String kind);

  /// No description provided for @identityTitle.
  ///
  /// In it, this message translates to:
  /// **'Scheda dispositivo'**
  String get identityTitle;

  /// No description provided for @identityCustomName.
  ///
  /// In it, this message translates to:
  /// **'Nome personalizzato'**
  String get identityCustomName;

  /// No description provided for @identityField.
  ///
  /// In it, this message translates to:
  /// **'{field, select, HOSTNAME{Nome di rete} MANUFACTURER{Produttore} MODEL{Modello} PRODUCT_CODE{Codice prodotto} FIRMWARE{Firmware} OS{Sistema operativo} DEVICE_TYPE{Categoria} CPE{CPE} other{{field}}}'**
  String identityField(String field);

  /// No description provided for @identityStatus.
  ///
  /// In it, this message translates to:
  /// **'{status, select, VERIFIED{Verificato} PROBABLE{Probabile} other{Sconosciuto}}'**
  String identityStatus(String status);

  /// No description provided for @identitySources.
  ///
  /// In it, this message translates to:
  /// **'Fonti'**
  String get identitySources;

  /// No description provided for @identityUserConfirmed.
  ///
  /// In it, this message translates to:
  /// **'confermato dall\'utente'**
  String get identityUserConfirmed;

  /// No description provided for @identityConflict.
  ///
  /// In it, this message translates to:
  /// **'fonti in disaccordo'**
  String get identityConflict;

  /// No description provided for @identityStatusRule.
  ///
  /// In it, this message translates to:
  /// **'Verificato: dichiarato dal dispositivo, confermato dall\'utente o da due fonti indipendenti concordanti. Le correzioni si fanno dalla dashboard web.'**
  String get identityStatusRule;

  /// No description provided for @identityHistory.
  ///
  /// In it, this message translates to:
  /// **'Storico identificazione'**
  String get identityHistory;

  /// No description provided for @identityOrigin.
  ///
  /// In it, this message translates to:
  /// **'{origin, select, USER{modifica utente} other{scansione}}'**
  String identityOrigin(String origin);

  /// No description provided for @openPorts.
  ///
  /// In it, this message translates to:
  /// **'Servizi esposti in rete'**
  String get openPorts;

  /// No description provided for @noOpenPorts.
  ///
  /// In it, this message translates to:
  /// **'Nessuna porta aperta rilevata dall\'ultima scansione delle porte.'**
  String get noOpenPorts;

  /// No description provided for @confidence.
  ///
  /// In it, this message translates to:
  /// **'{level, select, HIGH{Alta} MEDIUM{Media} LOW{Bassa} other{-}}'**
  String confidence(String level);

  /// No description provided for @category.
  ///
  /// In it, this message translates to:
  /// **'{category, select, ROUTER{Router} IP_CAMERA{Videocamera} SMART_TV{Smart TV} SMARTPHONE{Smartphone} TABLET{Tablet} LAPTOP{Portatile} DESKTOP{Computer} PRINTER{Stampante} NAS{NAS} SMART_PLUG{Presa smart} SMART_SPEAKER{Altoparlante smart} IOT{Dispositivo IoT} VOIP_PHONE{Telefono VoIP} NETWORK_DEVICE{Apparato di rete} SERVER{Server} other{Non identificato}}'**
  String category(String category);

  /// No description provided for @scans.
  ///
  /// In it, this message translates to:
  /// **'Scansioni'**
  String get scans;

  /// No description provided for @noScans.
  ///
  /// In it, this message translates to:
  /// **'Nessuna scansione.'**
  String get noScans;

  /// No description provided for @newScan.
  ///
  /// In it, this message translates to:
  /// **'Nuova scansione'**
  String get newScan;

  /// No description provided for @scanProfile.
  ///
  /// In it, this message translates to:
  /// **'{profile, select, DISCOVERY{Rilevamento} QUICK{Rapida} STANDARD{Standard} other{{profile}}}'**
  String scanProfile(String profile);

  /// No description provided for @scanProfileHelp.
  ///
  /// In it, this message translates to:
  /// **'{profile, select, DISCOVERY{Trova i dispositivi in rete, senza controllare i servizi.} QUICK{Dispositivi e porte più comuni: pochi minuti.} STANDARD{Dispositivi, porte e servizi: analisi completa.} other{}}'**
  String scanProfileHelp(String profile);

  /// No description provided for @scanConfirm.
  ///
  /// In it, this message translates to:
  /// **'La scansione è eseguita dall\'agent installato in casa, solo sulle reti che hai autorizzato e senza tentativi di accesso ai dispositivi.'**
  String get scanConfirm;

  /// No description provided for @start.
  ///
  /// In it, this message translates to:
  /// **'Avvia'**
  String get start;

  /// No description provided for @cancel.
  ///
  /// In it, this message translates to:
  /// **'Annulla'**
  String get cancel;

  /// No description provided for @stopScan.
  ///
  /// In it, this message translates to:
  /// **'Interrompi'**
  String get stopScan;

  /// No description provided for @scanStatus.
  ///
  /// In it, this message translates to:
  /// **'{status, select, PENDING{In attesa} QUEUED{In coda} RUNNING{In corso} COMPLETED{Completata} COMPLETED_WITH_WARNINGS{Completata con avvisi} FAILED{Non riuscita} CANCELLED{Annullata} other{{status}}}'**
  String scanStatus(String status);

  /// No description provided for @scanProgress.
  ///
  /// In it, this message translates to:
  /// **'{percent}%'**
  String scanProgress(int percent);

  /// No description provided for @scanDevices.
  ///
  /// In it, this message translates to:
  /// **'{count, plural, =0{Nessun dispositivo trovato} =1{1 dispositivo trovato} other{{count} dispositivi trovati}}'**
  String scanDevices(int count);

  /// No description provided for @scanFailure.
  ///
  /// In it, this message translates to:
  /// **'Motivo: {reason}'**
  String scanFailure(String reason);

  /// No description provided for @scanCancelRequested.
  ///
  /// In it, this message translates to:
  /// **'Annullamento richiesto'**
  String get scanCancelRequested;

  /// No description provided for @scanError.
  ///
  /// In it, this message translates to:
  /// **'{code, select, NO_AUTHORIZED_NETWORK{Nessuna rete autorizzata: autorizzala dalla dashboard web.} AGENT_OFFLINE{L\'agent dell\'abitazione non è raggiungibile.} SCAN_ALREADY_ACTIVE{C\'è già una scansione in corso.} PROFILE_NOT_AVAILABLE{Profilo non disponibile per questo agent.} other{Impossibile avviare la scansione.}}'**
  String scanError(String code);

  /// No description provided for @alertTitle.
  ///
  /// In it, this message translates to:
  /// **'{type, select, NEW_FINDING{Nuovo problema di sicurezza} FINDING_RESOLVED{Problema risolto} SCORE_DROPPED{Il punteggio è sceso} NEW_DEVICE{Nuovo dispositivo in rete} SCAN_FAILED{Scansione non riuscita} AGENT_OFFLINE{Agent non raggiungibile} other{Avviso}}'**
  String alertTitle(String type);

  /// No description provided for @alertScore.
  ///
  /// In it, this message translates to:
  /// **'Ora {score}/100 ({change} punti)'**
  String alertScore(int score, int change);

  /// No description provided for @alertDevices.
  ///
  /// In it, this message translates to:
  /// **'{count, plural, =1{1 dispositivo nuovo} other{{count} dispositivi nuovi}}'**
  String alertDevices(int count);

  /// No description provided for @alertAgent.
  ///
  /// In it, this message translates to:
  /// **'Agent \"{name}\" senza contatto da più di 15 minuti'**
  String alertAgent(String name);

  /// No description provided for @occurrences.
  ///
  /// In it, this message translates to:
  /// **'Ripetuto {count} volte'**
  String occurrences(int count);

  /// No description provided for @resolved.
  ///
  /// In it, this message translates to:
  /// **'Risolto'**
  String get resolved;

  /// No description provided for @markRead.
  ///
  /// In it, this message translates to:
  /// **'Segna come letto'**
  String get markRead;

  /// No description provided for @markAllRead.
  ///
  /// In it, this message translates to:
  /// **'Segna tutti come letti'**
  String get markAllRead;

  /// No description provided for @unreadOnly.
  ///
  /// In it, this message translates to:
  /// **'Solo da leggere'**
  String get unreadOnly;

  /// No description provided for @noAlerts.
  ///
  /// In it, this message translates to:
  /// **'Nessun avviso.'**
  String get noAlerts;

  /// No description provided for @pushDisabled.
  ///
  /// In it, this message translates to:
  /// **'Notifiche push non configurate in questa build.'**
  String get pushDisabled;

  /// No description provided for @viewDevices.
  ///
  /// In it, this message translates to:
  /// **'Dispositivi'**
  String get viewDevices;

  /// No description provided for @viewScans.
  ///
  /// In it, this message translates to:
  /// **'Scansioni'**
  String get viewScans;

  /// No description provided for @peopleTitle.
  ///
  /// In it, this message translates to:
  /// **'Persone'**
  String get peopleTitle;

  /// No description provided for @peopleNone.
  ///
  /// In it, this message translates to:
  /// **'Nessuna persona associata. Le associazioni si gestiscono dalla dashboard web.'**
  String get peopleNone;

  /// No description provided for @personStatus.
  ///
  /// In it, this message translates to:
  /// **'{status, select, CONFIRMED{Confermata} other{Probabile}}'**
  String personStatus(String status);

  /// No description provided for @personSource.
  ///
  /// In it, this message translates to:
  /// **'{source, select, DEVICE_NAME{dal nome del dispositivo} HOME_ASSISTANT{da Home Assistant} DIRECTORY{da Active Directory} FIREWALL{dal firewall} other{inserita a mano}}'**
  String personSource(String source);
}

class _AppLocalizationsDelegate
    extends LocalizationsDelegate<AppLocalizations> {
  const _AppLocalizationsDelegate();

  @override
  Future<AppLocalizations> load(Locale locale) {
    return SynchronousFuture<AppLocalizations>(lookupAppLocalizations(locale));
  }

  @override
  bool isSupported(Locale locale) =>
      <String>['en', 'it'].contains(locale.languageCode);

  @override
  bool shouldReload(_AppLocalizationsDelegate old) => false;
}

AppLocalizations lookupAppLocalizations(Locale locale) {
  // Lookup logic when only language code is specified.
  switch (locale.languageCode) {
    case 'en':
      return AppLocalizationsEn();
    case 'it':
      return AppLocalizationsIt();
  }

  throw FlutterError(
    'AppLocalizations.delegate failed to load unsupported locale "$locale". This is likely '
    'an issue with the localizations generation tool. Please file an issue '
    'on GitHub with a reproducible sample app and the gen-l10n configuration '
    'that was used.',
  );
}
