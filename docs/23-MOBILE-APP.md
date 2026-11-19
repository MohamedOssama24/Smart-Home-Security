# 23 — App mobile Flutter (Milestone 14)

La M14 aggiunge l'app Android/iOS in `mobile/shsc_app`. L'app usa le API e gli account esistenti e offre:
- login;
- dashboard delle abitazioni;
- dispositivi;
- scansione manuale;
- avvisi con notifiche push FCM.

Registrazione, reset della password, gestione di utenti, reti e agent restano nella dashboard web.

Le decisioni sono ADR-068 (dipendenze) e ADR-069 (autenticazione mobile e push).

## 1. Funzioni

| Schermata | Percorso | API | Permesso |
|---|---|---|---|
| Accesso | `/login` | `POST /auth/mobile/login`, `GET /me` | — |
| Abitazioni (dalla più a rischio) | `/` | `GET /overview` | `home:read`; punteggio e problemi con `finding:read` |
| Dashboard abitazione | `/homes/:id` | `GET /overview` | come sopra |
| Dispositivi | `/homes/:id/devices` | `GET /homes/{id}/devices` | `device:read` |
| Dettaglio dispositivo | `/devices/:id` | `GET /devices/{id}` | `device:read` |
| Scansioni e nuova scansione | `/homes/:id/scans` | `GET`/`POST /homes/{id}/scans` (con `Idempotency-Key`) | `scan:read`, `scan:create` |
| Stato della scansione | `/scans/:id` | `GET /scans/{id}` ogni 3 s finché è attiva, `POST /scans/{id}/cancel` | `scan:read`, `scan:create` |
| Avvisi | `/alerts` | `GET /alerts`, `/alerts/unread-count`, `POST /alerts/{id}/read`, `/alerts/read-all` | quello del tipo di alert |

- **Pulsanti e voci**: sono nascosti senza il permesso. L'autorizzazione resta sempre al backend.
- **Dashboard abitazione**: punteggio con livello di rischio, variazione e avviso "provvisorio"; problemi per gravità; vulnerabilità sfruttate attivamente (KEV); dispositivi; ultima scansione.
- **Dettaglio dispositivo**: tipo e affidabilità, IP, MAC (anche casuale), produttore, modello, sistema operativo e servizi esposti dall'ultima scansione delle porte.
- **Scansione manuale**:
  - si sceglie il profilo (Rilevamento, Rapida, Standard);
  - prima dell'avvio l'app ricorda che la scansione è eseguita dall'agent di casa, solo sulle reti autorizzate e senza tentativi di accesso;
  - il telefono non scansiona nulla;
  - gli errori del backend (`AGENT_OFFLINE`, `NO_AUTHORIZED_NETWORK`, `SCAN_ALREADY_ACTIVE`, `PROFILE_NOT_AVAILABLE`) sono mostrati con un testo comprensibile.
- **Avvisi**:
  - testo costruito dal payload, come nella dashboard;
  - gravità, abitazione, occorrenze, "Risolto";
  - lettura singola e totale; il contatore dei non letti compare nell'intestazione.
- **Lingua**: IT/EN secondo la lingua del dispositivo, italiano se non supportata.
- **Tema**: chiaro e scuro.

## 2. Autenticazione mobile
I percorsi `POST /api/v1/auth/mobile/login`, `/refresh` e `/logout` usano le stesse sessioni del web:
- rotazione del refresh token a ogni rinnovo;
- riuso di un token già usato → revoca dell'intera sessione;
- blocco progressivo e audit.

Rispetto al web:
- il refresh token è restituito e ricevuto **nel body JSON**, mai in un cookie;
- i tre percorsi sono **esclusi dal CSRF** (`SecurityConfig.COOKIE_ENDPOINTS`): non leggono cookie e richiedono un token che solo l'app possiede;
- il limite di Nginx su `/api/v1/auth/` si applica anche a loro.

Risposta di login e refresh: `{accessToken, tokenType, expiresIn, expiresAt, sessionId, refreshToken, refreshExpiresAt}`.

**Nell'app**:
- **Token di accesso**: solo in memoria.
- **Refresh token**: in `flutter_secure_storage`.
  - Android Keystore, con il backup dell'app disattivato.
  - iOS Keychain `first_unlock_this_device`: non è ripristinato su un altro dispositivo.
- **Rinnovo**: a un `401` l'app rinnova la sessione una sola volta (le richieste parallele condividono il rinnovo) e ripete la richiesta.
- **Sessione persa**: se il rinnovo fallisce l'app torna al login con "La sessione è scaduta".
- **Avvio**: l'app riprende la sessione salvata senza chiedere la password.
- **HTTPS obbligatorio**: HTTP è accettato solo verso `localhost`, `127.0.0.1` e `10.0.2.2` fuori dalle build release; Android vieta il traffico in chiaro.

## 3. Notifiche push

### API
| Metodo | Percorso | Note |
|---|---|---|
| `POST` | `/push-devices` | `{token, platform: ANDROID\|IOS, locale: it\|en}` → `201`; stesso token = stessa registrazione (aggiornata alla sessione corrente); il token non è mai restituito |
| `GET` | `/push-devices` | registrazioni dell'utente, con `currentSession` e `pushEnabled` |
| `DELETE` | `/push-devices/{id}` | `204`; `404` se non è dell'utente |

Registrazione e rimozione sono registrate nell'audit (`PUSH_DEVICE_REGISTERED`, `PUSH_DEVICE_REMOVED`).

### Comportamento
- **Registrazione**: dopo il login, se l'utente concede il permesso di notifica (Android 13+, iOS), l'app registra il token FCM. Lo registra di nuovo quando il token cambia e lo cancella al logout.
- **Legame con la sessione**: ogni registrazione è legata alla sessione di login. Logout, revoca della sessione o cambio password fermano subito le notifiche.
- **Canale `PUSH`**:
  - si aggiunge a `DASHBOARD` ed `EMAIL` nelle preferenze (predefinito: da `MEDIUM` in su);
  - una consegna nasce solo se FCM è configurato e l'utente ha almeno un'app collegata;
  - la dashboard web continua a mostrare solo dashboard ed email; le preferenze push si salvano con lo stesso `PUT /notification-preferences`.
- **Invio**:
  - lo stesso job delle email (ogni 30 s) invia a ogni app collegata;
  - un token non più valido (`UNREGISTERED`, 404) viene rimosso;
  - un errore temporaneo è ritentato a 5 e 15 minuti, poi la consegna è `FAILED PUSH_ERROR`;
  - senza app valide la consegna è `FAILED NO_PUSH_DEVICE`.
- **Contenuto**: il titolo è lo stesso dell'oggetto dell'email, nella lingua dell'app; il testo è il nome dell'abitazione. Nei dati ci sono solo `alertId`, `homeId` e `type`: nessun IP, nessuna evidenza.
- **Nell'app**:
  - toccando una notifica si aprono gli avvisi;
  - una notifica ricevuta con l'app aperta aggiorna il contatore e mostra un messaggio breve.

### Configurazione (a cura del proprietario, gratuita)
- **Backend**:
  - `SHSC_FCM_PROJECT_ID`;
  - `SHSC_FCM_CREDENTIALS_FILE`: il JSON del service account scaricato dalla console Firebase, montato come file segreto.
  - Senza queste variabili il push è disattivato e il resto funziona.
- **App**: `--dart-define` con `SHSC_FIREBASE_API_KEY`, `SHSC_FIREBASE_APP_ID`, `SHSC_FIREBASE_SENDER_ID` e `SHSC_FIREBASE_PROJECT_ID`. Sono identificativi pubblici, non segreti. Senza di essi l'app funziona senza notifiche.
- **iOS**: servono anche la capability Push Notifications e la chiave APNs caricata in Firebase.

## 4. Build e avvio
Flutter non è installato sul PC: si usa l'immagine Docker `ghcr.io/cirruslabs/flutter:3.44.0`, la stessa della CI.

```
docker run --rm -v "<repo>/mobile/shsc_app:/work" -w /work ghcr.io/cirruslabs/flutter:3.44.0 flutter test
flutter build apk --dart-define=SHSC_API_BASE_URL=https://<dominio> [--dart-define=SHSC_FIREBASE_...]
```

- **Indirizzo predefinito**: `https://10.0.2.2`, cioè l'host visto dall'emulatore Android.
- **Certificato**: il certificato autofirmato di sviluppo non è accettato dall'app. Non è stata aggiunta alcuna eccezione TLS: serve un certificato valido o un tunnel.

## 5. Test

### Backend
- **`MobileApiTest`** (integrazione, 3 test):
  - login mobile senza cookie e senza CSRF;
  - rotazione, riuso rifiutato con revoca della sessione;
  - il refresh web resta protetto dal CSRF;
  - registrazioni validate, token mai restituito, isolamento tra tenant;
  - alert `SCAN_FAILED` inviato in push nella lingua del dispositivo, token non valido rimosso;
  - nessuna consegna senza FCM configurato;
  - logout che ferma le notifiche.
  - Il gateway FCM è simulato.
- **`FcmPushGatewayTest`** (3 test): server locale `[MOCK]` che fa da OAuth Google e FCM.
  - Verifica la firma RS256 dell'assertion e il token in cache.
  - Verifica il formato del messaggio e la gestione degli errori (`UNREGISTERED`, `INVALID_ARGUMENT`, `503`).

### App (`flutter test`, backend `[MOCK]` in memoria)
- **`api_test`** (3 test): un solo rinnovo per più `401` paralleli, codici di errore, regola HTTPS.
- **`auth_test`** (5 test): validazione, credenziali errate, login con registrazione push, sessione ripresa all'avvio, rotazione trasparente, sessione revocata, logout, permesso push rifiutato, interfaccia in inglese.
- **`dashboard_test`** (3 test): abitazioni, punteggio e problemi, dispositivi e servizi, permessi mancanti, server non raggiungibile.
- **`scan_alerts_test`** (3 test): scansione con conferma, profilo e `Idempotency-Key`, seguita fino al completamento; errore `AGENT_OFFLINE`; nessun pulsante senza `scan:create`; avvisi, lettura e apertura da notifica.

### Integrazione
- **`test/integration/app_flow_test`**: l'intera app su HTTP reale (socket di `dio`) contro l'API `[MOCK]` servita su localhost. Copre login, push, dashboard, dispositivi, scansione fino al completamento, avvisi da notifica e logout.
- **`integration_test/app_test.dart`**: lo stesso flusso su emulatore o dispositivo (`flutter test integration_test -d <device>`).

### CI
Job `mobile`: `flutter analyze`, `flutter test` e `flutter build apk --debug`.

## 6. Sicurezza
- **Dati sul telefono**: nessuna credenziale salvata oltre al refresh token, nessun dato di sicurezza in cache su disco.
- **Log**: nessun token nei log, né nell'app né nel backend.
- **Rete**: solo HTTPS, nessun redirect seguito.
- **Notifiche**: senza dati personali, perché la schermata di blocco è visibile a chiunque.
- **Permessi**: l'app mostra solo ciò che il backend permette e non aggiunge controlli propri.

## 7. Limiti
- **Verifiche non eseguite**: nessuna prova su emulatore o dispositivo fisico e nessun invio FCM reale; manca un progetto Firebase del proprietario. Le verifiche reali sono rimandate alla M18.
- **Build**: verificata solo la build Android debug. La build iOS richiede macOS e Xcode.
- **API FCM**: `getToken`/`onTokenRefresh` sono deprecati in `firebase_messaging` 17 (ADR-068).
- **Funzioni non presenti nell'app**:
  - MFA (non ancora implementata nel backend);
  - registrazione e reset della password (nel web);
  - gestione di reti e agent, triage dei problemi, report PDF (in seguito, se richiesti);
  - testi dei problemi solo per tipo e gravità: il titolo della regola è nella dashboard web.
- **Preferenze push**: si salvano con l'API; la tabella della dashboard web mostra ancora solo dashboard ed email.
