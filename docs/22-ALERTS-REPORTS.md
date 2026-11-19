# 22 — Alert e report PDF (Milestone 13)

La M13 aggiunge:
- gli **alert** con deduplicazione e preferenze di notifica;
- l'invio via **email SMTP**;
- i **report PDF** di una scansione, in italiano e inglese.

Le notifiche push sono state aggiunte con l'app nella M14: canale `PUSH` ([23-MOBILE-APP.md](23-MOBILE-APP.md) §3).

## 1. Alert

| Tipo | Quando | Gravità | Chiave di deduplicazione | Risolto quando | Permesso per riceverlo |
|---|---|---|---|---|---|
| `NEW_FINDING` | la scansione vede un finding aperto di gravità alta o critica | quella del finding | `finding:<id>` | il finding è risolto da una scansione o segnato come falso positivo o rischio accettato | `finding:read` |
| `FINDING_RESOLVED` | una scansione risolve un finding che aveva un alert | `INFO` | `resolved:<finding>:<scan>` (evento) | — | `finding:read` |
| `SCORE_DROPPED` | il punteggio scende di almeno 10 punti, o scende e il livello di rischio peggiora | `MEDIUM`, `HIGH` o `CRITICAL` secondo il nuovo livello | `score-drop:<home>` | il punteggio risale | `finding:read` |
| `NEW_DEVICE` | dispositivi visti per la prima volta, esclusa la prima scansione dell'abitazione | `LOW` | `device:<id>`; oltre 10 dispositivi un solo alert `devices:<scan>` | — | `device:read` |
| `SCAN_FAILED` | una scansione termina `FAILED` | `MEDIUM` | `scan-failed:<home>` | la scansione successiva è completata | `scan:read` |
| `AGENT_OFFLINE` | un agent attivo è senza heartbeat da 15 minuti | `MEDIUM` | `agent-offline:<agent>` | l'heartbeat successivo | `agent:read` |

**Quando nascono**: gli alert sono creati nella stessa transazione dell'evento: completamento della scansione (dopo analisi e punteggio), fallimento, triage, heartbeat. Fa eccezione `AGENT_OFFLINE`, creato da un job periodico.

### Deduplicazione
- Esiste al più un alert **non risolto** per chiave: un indice unico parziale su `(tenant_id, dedup_key) WHERE resolved_at IS NULL`.
- Lo stesso evento ripetuto incrementa `occurrences` e `last_at`, senza nuove email e senza rimettere l'alert tra quelli da leggere.
  - Esempio: un finding visto da 5 scansioni produce un solo alert con 5 occorrenze.
- Dopo la risoluzione, un nuovo evento con la stessa chiave crea un nuovo alert.
  - Esempio: un problema che si ripresenta.

### Destinatari e canali
- **Destinatari**: alla creazione, gli utenti attivi e verificati del tenant che hanno il permesso del tipo sull'abitazione (scope TENANT, CUSTOMER o HOME).
- **Canali**: per ogni destinatario e canale (`DASHBOARD`, `EMAIL`) si applicano le preferenze:
  - ogni tipo può essere attivo o no, con una gravità minima;
  - predefiniti: tutto in dashboard, email da `MEDIUM` in su.
- **Rilettura**: i permessi sono ricontrollati quando l'utente legge, così un ruolo revocato nasconde subito gli alert.
- **Stato di lettura**: è per utente (`alert_deliveries.read_at`).

### Email
- **Invio**: un job ogni 30 secondi invia le consegne `PENDING` via SMTP; Mailpit in sviluppo.
- **Errori**: dopo un errore riprova dopo 5 e poi 15 minuti; al terzo errore la consegna è `FAILED` con il codice `SMTP_ERROR`. L'alert resta in dashboard.
- **Lingua**: quella dell'utente.
- **Contenuto**: titolo, abitazione, dispositivo, "Cosa fare" per i nuovi problemi, link alla dashboard e alle preferenze.
  - Nessuna evidenza tecnica, nessun token.
  - Nei log non finiscono né indirizzo né testo.

## 2. API
| Metodo | Percorso | Note |
|---|---|---|
| `GET` | `/alerts?unread&limit` | alert dell'utente, al massimo 200 (`400 INVALID_LIMIT`) |
| `GET` | `/alerts/unread-count` | numero per il menu |
| `POST` | `/alerts/{id}/read` | `204`; `404` se l'alert non è dell'utente |
| `POST` | `/alerts/read-all` | `{count}` |
| `GET` | `/notification-preferences` | tutte le combinazioni tipo × canale, anche quelle predefinite |
| `PUT` | `/notification-preferences` | `{items:[{type, channel, enabled, minSeverity}]}` (`400 INVALID_PREFERENCE`) |
| `POST` | `/scans/{scanId}/reports` | `{locale: it\|en}` → `202` `PENDING` |
| `GET` | `/reports/{id}` | stato |
| `GET` | `/homes/{homeId}/reports` | ultimi 50 |
| `GET` | `/reports/{id}/download` | `application/pdf`, `attachment`, `no-store` |

**Errori della richiesta di report**:
- `400 INVALID_LOCALE`;
- `409 SCAN_NOT_COMPLETED`;
- `409 REPORT_IN_PROGRESS`, se lo stesso report è già in preparazione;
- `429 REPORT_LIMIT`, oltre 20 report per abitazione in 24 ore (limite provvisorio fino ai piani della M17).

## 3. Report PDF
- **Permessi**:
  - per generarlo servono `report:generate` (nuovo permesso: SUPER_ADMIN, ORGANIZATION_ADMIN, TECHNICIAN, CUSTOMER) **e** `finding:read`;
  - per leggerlo e scaricarlo basta `finding:read`.
  - La richiesta e il download sono registrati nell'audit.
- **Generazione**:
  - parte in background dopo il commit della richiesta;
  - i dati vengono letti in una transazione, il PDF è disegnato fuori dalla transazione e poi salvato (`READY`);
  - un errore porta a `FAILED GENERATION_FAILED`;
  - un report rimasto `PENDING` per oltre 10 minuti, per esempio per un riavvio, risulta `FAILED INTERRUPTED`.
- **Contenuto**, per lettori non tecnici (A4):
  1. abitazione, data, tipo e data della scansione;
  2. riepilogo:
     - punteggio con livello e giudizio, e cosa significa;
     - copertura, con dispositivi analizzati su quelli trovati;
     - avviso "provvisorio";
     - problemi aperti per gravità e rischi accettati;
     - motivo se il punteggio non è calcolato (`DISCOVERY`);
  3. problemi da risolvere, dal più grave:
     - titolo, gravità, tipo (confermato, potenziale, configurazione…) e stato;
     - dispositivo;
     - "Cosa significa" e "Cosa fare";
     - al massimo 100;
  4. dispositivi trovati, al massimo 300;
  5. limiti dell'analisi (docs/10).
- **Dati**:
  - il punteggio è quello dell'ultimo snapshot della scansione;
  - i problemi e i dispositivi sono nello stato al momento della generazione, come scritto nel PDF.
- **Testi**:
  - le etichette del report sono in `messages*.properties` (`report.*`);
  - i testi delle regole, delle gravità e delle categorie vengono dalla dashboard (`resources/reports/texts_{it,en}.json`). Si copiano con `node infrastructure/scripts/sync-report-texts.mjs`.
  - Un test verifica che ogni regola abbia titolo e raccomandazione in entrambe le lingue.
- **Font**: font PDF standard (Helvetica), senza font incorporati. I caratteri che non possono rappresentare sono sostituiti da `?`.
- **Riproducibilità**: date e ID del documento sono fissati, quindi dagli stessi dati si ottengono gli stessi byte.

## 4. Dashboard
- **`/alerts`**:
  - elenco con testo costruito dal payload, gravità, abitazione, dispositivo, occorrenze e "Risolto";
  - filtro "Solo da leggere"; "Segna come letto" e "Segna tutti come letti";
  - link alla pagina pertinente.
- **Menu**: la voce "Avvisi" mostra il numero da leggere, aggiornato a ogni cambio pagina.
- **`/alerts/preferences`**: tabella tipo × canale, con attivo e gravità minima.
- **`/homes/:id/reports`**:
  - elenco dei report con stato, pagine e dimensione;
  - generazione da una scansione completata, in IT o EN, visibile solo con `report:generate`;
  - aggiornamento automatico fino a "Pronto";
  - download del PDF con il token di accesso.
- **Dettaglio abitazione**: ha un link ai report.

## 5. Test
- **`ReportRendererTest`** (unit):
  - **snapshot**: il testo dei PDF IT ed EN di un'abitazione `[MOCK]` è confrontato con `src/test/resources/reports/report-{it,en}.txt`; stessi byte a ogni rendering;
  - report lungo su più pagine con piè di pagina numerati e troncamento;
  - testi di tutte le regole.
  - Se lo snapshot cambia, il nuovo testo e il PDF sono in `target/report-snapshots`: va rivisto e copiato.
- **`AlertsReportsTest`** (integrazione):
  - deduplicazione: stesso finding in due scansioni, un alert con 2 occorrenze e una sola email;
  - email via SMTP simulato;
  - preferenze (email per i nuovi dispositivi, nessun alert in dashboard per le risoluzioni);
  - risoluzione del finding, nuovo dispositivo, calo del punteggio, lettura singola e totale;
  - un altro tenant non vede né modifica nulla;
  - scansioni fallite aggregate e poi risolte; agent offline creato una sola volta e risolto dall'heartbeat;
  - report: generazione EN, download con hash verificato e testo, `400` / `409`, `READ_ONLY` legge ma non genera (`403`), altro tenant `404`.
- **Frontend**:
  - `alerts.page.spec` (3 test, preferenze incluse);
  - `reports.page.spec` (2 test).
- **E2E**: il contatore degli alert non letti nel menu.

## 6. Limiti
- **Canali**: niente ore di silenzio (il push è arrivato con la M14). La colonna `quiet_hours` di docs/04 non è stata creata.
- **Avvisi di sicurezza dell'account**: non ci sono alert come il riuso di un refresh token (docs/06); restano audit e revoca automatica.
- **Code**: la coda email e i report sono nel database: nessun broker, nessun object storage (ADR-067).
- **Limiti dei report**: per abitazione al giorno; i limiti per piano arrivano con la M17.
- **Font**: un PDF con caratteri non latini (per esempio un nome di dispositivo in cinese) li mostra come `?`.
