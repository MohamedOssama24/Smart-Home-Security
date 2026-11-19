# Project Status

**Ultimo aggiornamento**: 19/11/2026
**Posizione**: `C:\Users\mohamed\Desktop\smart-home-security-check` (repository git dedicato, branch `main`; commit iniziale `4b89721` pubblicato su GitHub `MohamedOssama24/Smart-Home-Security`; M5–M18 committate sul branch `release/m5-m18`)
**Milestone corrente**: 18 — Hardening, test e rilascio → **COMPLETATA e approvata** (19/11/2026; restano verifiche che richiedono risorse del titolare: vedi Riepilogo M18)
**Prossima milestone**: nessuna (M18 è l'ultima della roadmap): rilascio dopo approvazione

## Milestone
| # | Milestone | Stato |
|---|---|---|
| 1 | Analisi e architettura | ✅ Completata |
| 2 | Infrastructure & Docker | ✅ Completata |
| 3 | Autenticazione, sessioni, RBAC, identità agent | ✅ Completata e approvata |
| 4 | Utenti, organizzazioni, clienti, homes, reti, limiti piano FREE | ✅ Completata e approvata |
| 5 | Agent Core Go ed enrollment | ✅ Completata e approvata |
| 6 | Workflow scansioni manuali | ✅ Completata e approvata |
| 7 | Network Discovery completa | ✅ Completata e approvata (prova su LAN reale rimandata alla M18) |
| 8 | Fingerprinting e classificazione dispositivi | ✅ Completata e approvata |
| 9 | Rilevamento porte e servizi | ✅ Completata e approvata |
| 10 | Analisi sicurezza e vulnerabilità | ✅ Completata e approvata (prova con feed NVD e dispositivi reali rimandata alla M18) |
| 11 | Motore di rischio | ✅ Completata e approvata |
| 12 | Dashboard Angular completa | ✅ Completata e approvata |
| 13 | Alert e report PDF | ✅ Completata e approvata |
| 14 | App Flutter | ✅ Completata e approvata (prova su dispositivo e FCM reale rimandate alla M18) |
| 15 | Integrazioni: Home Assistant, valutazione Matter | ✅ Completata e approvata (route `/homes/{homeId}/integrations` non implementate per ADR-070) |
| 16 | AI Security Assistant | ✅ Completata e approvata |
| 17 | SaaS, Stripe e White Label | ✅ Completata e approvata (prova con Stripe test mode reale e doppio checkout rimandati alla M18) |
| 18 | Hardening, test e rilascio | ✅ Completata e approvata (Stripe reale, LAN reale, dispositivo mobile/FCM da fare con risorse del titolare) |

## Milestone 18 — Riepilogo
Dettagli in [docs/27-RELEASE-HARDENING.md](docs/27-RELEASE-HARDENING.md); guida utente in [docs/28-USER-GUIDE.md](docs/28-USER-GUIDE.md).

### Problemi risolti
- **Doppio checkout Stripe** (criticità M17): checkout serializzati per tenant (lock), verifica delle sottoscrizioni su Stripe, scadenza delle sessioni aperte, seconda sottoscrizione ignorata dal webhook con audit `duplicate`.
- **`stripe_webhook_events` senza RLS** (regressione M17 rilevata da `DatabaseBaselineTest`): migrazione V017 con policy `tenant_isolation`.
- **`restore-db.sh`** cercava le tabelle nello schema `public` invece di `shsc`.
- Firma delle release dell'agent (`shsc-release-sign`, Ed25519, ADR-073) integrata in `build-agent.sh`.
- Nuovi: `restore-db.sh` (verify/live), test opzionale dei feed reali `VulnerabilityLiveFeedTest`, docs 27 e 28; README aggiornato.

### Test
- Backend suite completa: primo giro 1 fallimento (`DatabaseBaselineTest`), corretto con V017; rieseguita dopo V017: 216 test, 0 fallimenti, 1 saltato (opzionale).
- Frontend 115/115 (28 file); Flutter analyze pulito e 15/15; agent Go vet + test OK.
- Feed reali: NVD 770, KEV 1786, EPSS 770, nessun errore.
- Pen-test interno non distruttivo: header, TLS ≥ 1.2, actuator 404, API 401, rate limit 429 (API e auth), webhook 404 senza chiavi e 413 oltre 256 KB.
- Firma agent: valida, file alterato rifiutato. Backup → restore verify: dump nuovo dopo V017 → Flyway V17, 0 migrazioni fallite, 43 tabelle RLS, dati uguali al live (il primo drill dava V16 perché il dump era precedente a V017).

### Criticità residue
- Stripe in test mode con account reale: servono le chiavi di test del titolare (`SHSC_STRIPE_*`).
- Scansioni su dispositivi reali: nessun accesso alla rete autorizzata `172.20.204.0/22` con dispositivi fisici.
- App mobile su dispositivo e FCM reale; MFA non implementata.
- Copia off-site cifrata dei backup e stack di metriche/alerting non automatizzati; chiave di firma definitiva, segreti di produzione e certificato TLS pubblico da predisporre al deploy.

## Milestone 17 — Riepilogo

**Obiettivo**: piani SaaS a pagamento con Stripe (Checkout, Billing Portal, webhook firmati) e white label per le organizzazioni, senza mescolare dati tra tenant. Dettagli in [docs/26-SAAS-BILLING.md](docs/26-SAAS-BILLING.md), decisione ADR-072.

### Funzionalità implementate
- Piani `PLUS` (privati) e `PRO` (aziende, white label) oltre a `FREE`; `plans.tenant_types` limita chi può sottoscriverli. Prezzi solo in Stripe (Price id in configurazione).
- `GET /billing`, `POST /billing/checkout`, `POST /billing/portal` (`billing:manage` a livello tenant): un cliente Stripe per tenant, una sola sottoscrizione attiva, URL restituiti solo se `https://checkout.stripe.com` o `billing.stripe.com`.
- `POST /billing/stripe/webhook` pubblico: firma HMAC-SHA256 (tolleranza 5 min), eventi idempotenti (`stripe_webhook_events`), tenant ricavato solo dal cliente Stripe salvato (funzione SECURITY DEFINER), mai dai metadati; eventi fuori ordine `STALE`; piano non ammesso per il tipo di tenant → FREE; downgrade senza cancellare dati.
- White label (`tenant_branding`, RLS): nome, colore, e-mail di supporto, logo PNG/JPEG validato (magic bytes, max 256 KB e 2048×2048, niente SVG). Applicato all'header della dashboard e all'intestazione dei report PDF solo finché il piano lo include.
- Client Stripe con `HttpClient` del JDK (nessuna nuova dipendenza); solo chiavi di test salvo `SHSC_STRIPE_ALLOW_LIVE=true`; senza chiavi gli abbonamenti online sono disattivati (503 `BILLING_DISABLED`).
- Dashboard: pagina `/billing` (piani, abbonamento, portale, white label), voce di menu, branding nell'header, i18n IT/EN.
- Prova gratuita (completata in revisione): durata `SHSC_STRIPE_TRIAL_DAYS` (0 = disattivata, max 730), una sola per tenant. Durante la prova vale il piano acquistato. A fine prova: pagamento riuscito → piano mantenuto; primo pagamento fallito → FREE subito, il piano torna se Stripe incassa; disdetta o nessuna carta → FREE. Downgrade senza cancellare dati, limiti applicati alle operazioni successive.

### File
- DB: `V015__saas_billing_branding.sql`, `V016__billing_trial.sql`. Backend: `com/shsc/billing/*` (7 classi), `Permissions.BILLING_MANAGE`, 4 `AuditAction`, `SecurityConfig` (webhook pubblico), `ReportData/Renderer/Service` (nome del brand), `application.yml`.
- Frontend: `core/billing/billing.api.ts`, `features/billing/billing.page.ts`, `app.ts/html/scss`, route, codici di errore, i18n.
- Config: `.env.example`, `docker-compose.yml`. Docs: 26 (nuovo), 05, README, ADR-072.

### Test
- `BillingIntegrationTest` 2/2 (server Stripe simulato [MOCK], incluso il caso della prova gratuita), `billing.page.spec` 2/2 (offerta di prova), `StripeWebhookVerifierTest` 2/2, `ReportRendererTest` 5/5 (incluso il brand nel PDF).
- Regressioni: `AlertsReportsTest`, `TenantIsolationAndRbacTest`, `CrossTenantIsolationTest`, `RoleAuthorizationMatrixTest`, `CustomersHomesAndPlanTest`: 22/22.
- Frontend: `billing.page.spec.ts` 2/2, `app.spec.ts` 2/2.

### Limiti
- Nessuna prova con un account Stripe reale (anche di test): verificato con un server simulato. Vanno configurati in Stripe Prodotti/Prezzi, endpoint webhook e Billing Portal. Prova in Stripe test mode rimandata alla M18.
- ~~Criticità doppio checkout~~ → **risolta nella M18** (vedi Riepilogo M18). Descrizione originale: due Checkout Session aperte in parallelo dallo stesso tenant e completate entrambe creano due sottoscrizioni Stripe (ognuna con la prova gratuita). Il controllo `SUBSCRIPTION_EXISTS` avviene solo alla creazione della sessione. Una delle due resterebbe attiva e addebitata in Stripe senza essere gestita dall'app. Da verificare e correggere nella M18.
- Nessuna area amministrativa (`/admin/**`) né elenco pagamenti (`GET /payments`): fatture e pagamenti sono nel Billing Portal di Stripe.
- Profili di scansione DEEP/CUSTOM legati al piano non implementati; il limite giornaliero dei report resta globale.
- Il white label non si applica a e-mail e app mobile; nessuna retention per `stripe_webhook_events`.

## Milestone 16 — Riepilogo

**Obiettivo**: assistente di sicurezza con porta `AssistantProvider` multi-provider, risposte solo dai dati del tenant, nessuna azione. Dettagli in [docs/25-AI-ASSISTANT.md](docs/25-AI-ASSISTANT.md), decisione ADR-071.

### Funzionalità implementate
- `POST /homes/{homeId}/assistant/questions`: `device:read` + `finding:read`, 404 per altri tenant, 20/min per utente, audit `ASSISTANT_QUERY` senza testo della domanda.
- Provider `LOCAL` deterministico (predefinito, IT/EN) e `OLLAMA` opzionale (JDK HttpClient, nessuna nuova dipendenza).
- `GroundingValidator`: citazioni obbligatorie e esistenti; IP, CVE, link e punteggi inventati rifiutati; fallback su LOCAL.
- Difesa da prompt injection: testi LAN ripuliti (controlli, link, 160 caratteri), dati e domanda in JSON per l'LLM.
- Pagina dashboard `/homes/:id/assistant` con fonti, provider, fallback e avviso di sola lettura.

### File
- Backend: `com/shsc/assistant/*` (8 classi), `AuditAction.ASSISTANT_QUERY`, `application.yml` (`shsc.assistant.*`).
- Frontend: `core/assistant/assistant.api.ts`, `features/assistant/assistant.page.ts`, route, link nel dettaglio casa, i18n IT/EN.
- Config: `.env.example`, `docker-compose.yml`. Docs: 25 (nuovo), 05, 21, README, ADR-071.

### Test
- `AssistantGroundingTest` 5/5, `AssistantIntegrationTest` 1/1 (backend).
- `assistant.page.spec.ts` 2/2 + `home-detail.page.spec.ts` 9/9 (frontend).

### Limiti
- Ollama verificato solo con un server HTTP simulato; nessun provider cloud (costo da decidere, ADR dedicato).
- Nessuna cronologia delle conversazioni; LOCAL copre un insieme finito di intenti; rate limit in memoria per istanza.
| F | Scan Scheduler automatico | 🚫 Fuori MVP (solo predisposto) |

## Milestone 15 — Riepilogo

**Obiettivo**: integrazione Home Assistant con API ufficiale e token di lunga durata del proprietario, valutazione Matter. Dettagli in [docs/24-INTEGRATIONS.md](docs/24-INTEGRATIONS.md), decisione ADR-070.

- **Agent**: `internal/homeassistant` (client chiuso: solo IP:porta configurati, niente proxy/redirect, TLS ≥ 1.2 verificato, 15 s, ≤ 4 MB). Usa solo `GET /api/config` e `POST /api/template`. Comando `shsc-agent homeassistant set|show|remove`, con token da stdin salvato in `homeassistant.json` protetto come la chiave. Contatto solo se l'IP è nell'ambito del job. Batch `homeAssistant` dedicato; avvisi `HA_*`.
- **Backend**: `V014__home_assistant.sql` (`scan_home_assistant`, `scan_gateway_devices`, RLS). Validazione del batch e ricontrollo dell'ambito; uno per scansione (409). `GET /scans/{id}/integrations` con conteggi per protocollo e `matchedIp` via MAC.
- **Dashboard**: sezione "Home Assistant" nel dettaglio scansione (protocolli, dispositivi, avviso HTTP in chiaro, troncamento); i18n IT/EN.
- **Matter**: tramite l'integrazione Matter di Home Assistant (adottata); mDNS passivo rimandato; controller proprio scartato.
- **Test**: backend `HomeAssistantIntegrationTest` 1/1 e regressioni NetworkDiscovery/ScanWorkflow/PortScanning/DatabaseBaseline 24/24. Agent gofmt/vet e test `homeassistant`, `scan`, `cli`, `identity` OK (Home Assistant **[MOCK]**). Dashboard `scans.page.spec` 6/6. Home Assistant reale 2026.11.2 in container (`infrastructure/scripts/test-homeassistant.sh`): PASS.
- **Non completato / limiti**:
  - mDNS Matter non implementato.
  - Test reale con token di onboarding (non long-lived creato da UI) e utente amministratore.
  - Dispositivi `demo` non presenti nell'inventario reale: la classificazione per protocollo è verificata solo con mock.
  - Correlazione solo via MAC.
  - Dati Home Assistant fuori dal punteggio di rischio.
  - Test con container non inserito nella CI.

## Milestone 14 — Riepilogo

**Obiettivo**: app Flutter Android/iOS con login, dashboard, dispositivi, scansione manuale e push FCM, riusando API e autenticazione esistenti. Dettagli in [docs/23-MOBILE-APP.md](docs/23-MOBILE-APP.md), decisioni ADR-068 (dipendenze Flutter) e ADR-069 (auth mobile + FCM).

### Funzionalità implementate
- **Auth mobile** `/api/v1/auth/mobile/{login,refresh,logout}`: stesse regole di sessione/rotazione del web, refresh token nel corpo JSON (no cookie, esente CSRF); nell'app salvato in secure storage, refresh single-flight su 401.
- **App**: login, elenco abitazioni con punteggio, dashboard abitazione, dispositivi e dettaglio, scansioni con richiesta manuale (profilo, Idempotency-Key) e avanzamento, avvisi con lettura; permessi rispettati; IT/EN.
- **Push**: registrazione dispositivo legata alla sessione (`/api/v1/push-devices`, token mai restituito, rimosso al logout/revoca); canale `PUSH` nelle preferenze (gravità minima default MEDIUM); job di invio FCM HTTP v1 solo JDK con ritentativi, token non validi eliminati. Disattivato senza `SHSC_FCM_PROJECT_ID`/`SHSC_FCM_CREDENTIALS_FILE`.
- **CI**: job `mobile` (analyze, test, build APK debug) con immagine Flutter 3.44.0.

### File
- **Database**: `V013__mobile_push.sql` (`push_devices` con RLS, canale PUSH, funzione `alert_deliveries_due`).
- **Backend**: `MobileAuthController`, pacchetto `alerts/push` (`PushGateway`, `FcmPushGateway`, `PushDeviceRepository`, `PushDeviceController`); modificati `AlertRepository`, `AlertService`, `AlertJobs`, `AlertType`, `AuditAction`, `SecurityConfig`, `application.yml`.
- **Test backend**: `MobileApiTest`, `FcmPushGatewayTest` (server locale `[MOCK]`), `IntegrationTest`, `AlertsReportsTest`.
- **App**: `mobile/shsc_app` (`lib/core`, `lib/ui`, `lib/l10n`, `test`, `integration_test`).
- **Infrastruttura/Docs**: `docker-compose.yml`, `.env.example`, `.github/workflows/ci.yml`; docs 05, 06, 22, 23 (nuovo), README, TECHNICAL_DECISIONS.

### Test
| Suite | Risultato |
|---|---|
| `MobileApiTest` (login/refresh/logout mobile, push device, tenant) | ✅ 3/3 |
| `FcmPushGatewayTest` (OAuth, invio, token non valido) | ✅ 3/3 |
| `AlertsReportsTest` (regressione canali) | ✅ 2/2 |
| Regressioni `AuthenticationSecurityTest`, `HttpSurfaceTest`, `DatabaseBaselineTest` | ✅ 34/34 |
| `flutter analyze` | ✅ nessun problema |
| `flutter test` (unit, widget, flusso integrato su HTTP reale) | ✅ 15/15 |
| `flutter build apk --debug` | ✅ |

### Problemi e note
- Regex Postgres `{20,4096}` oltre il limite di ripetizione: sostituita da `+` e controllo `length()`.
- `getToken`/`onTokenRefresh` di firebase_messaging deprecati senza alternativa stabile: mantenuti con commento.

### Limiti
- Nessun test su emulatore/dispositivo né con FCM reale; build iOS richiede macOS.
- Nessun MFA nell'app; il certificato self-signed di sviluppo non è accettato (serve certificato valido).
- La pagina web delle preferenze non mostra ancora la colonna PUSH (modificabile via API).

## Milestone 13 — Riepilogo

**Obiettivo**: alert con deduplicazione e preferenze, email SMTP, report PDF IT/EN. Dettagli in [docs/22-ALERTS-REPORTS.md](docs/22-ALERTS-REPORTS.md), decisioni ADR-066 (PDFBox) e ADR-067 (code nel database).

### Funzionalità implementate
- **Alert** `NEW_FINDING`, `FINDING_RESOLVED`, `SCORE_DROPPED`, `NEW_DEVICE`, `SCAN_FAILED`, `AGENT_OFFLINE`:
  - creati nella transazione dell'evento (completamento/fallimento scansione, triage, heartbeat); `AGENT_OFFLINE` da job periodico;
  - deduplicazione: un solo alert non risolto per chiave (indice unico parziale), occorrenze incrementate senza nuove email;
  - risoluzione automatica (finding risolto o triage, punteggio risalito, scansione completata, heartbeat).
- **Destinatari e preferenze**: utenti attivi con il permesso sull'abitazione; preferenze tipo × canale (`DASHBOARD`, `EMAIL`) con gravità minima; permessi ricontrollati in lettura; stato di lettura per utente.
- **Email SMTP**: job ogni 30 s, ritentativi a 5 e 15 minuti, poi `FAILED SMTP_ERROR`; lingua dell'utente; nessuna evidenza tecnica né dati personali nei log.
- **Report PDF** (PDFBox 3.0.8): IT/EN, generazione in background, riepilogo, problemi (max 100), dispositivi (max 300), limiti dell'analisi; byte deterministici; permesso nuovo `report:generate`; richiesta e download in audit; limite 20/abitazione/24 h.
- **API**: `/alerts`, `/alerts/unread-count`, `/alerts/{id}/read`, `/alerts/read-all`, `/notification-preferences`, `/scans/{id}/reports`, `/reports/{id}`, `/homes/{id}/reports`, `/reports/{id}/download`.
- **Dashboard**: pagine Avvisi (con contatore nel menu), Preferenze di notifica, Report dell'abitazione (generazione, aggiornamento fino a "Pronto", download); IT/EN.

### File
- **Database**: `V012__alerts_reports.sql` (tabelle `alerts`, `alert_deliveries`, `notification_preferences`, `reports`, RLS, permesso, funzioni per email e agent offline).
- **Backend (creati)**: pacchetti `alerts` (servizio, repository, mailer, job, controller) e `reports` (dati, renderer, servizio, controller); `shared/i18n/UiTexts`; `resources/reports/texts_{it,en}.json`; script `infrastructure/scripts/sync-report-texts.mjs`.
- **Backend (modificati)**: `pom.xml`, permessi, azioni di audit, `AgentJobService`, `ScanStateMachine`, `FindingService`, `AgentRuntimeService`, `application.yml`, `messages*.properties`.
- **Test**: `ReportRendererTest` con snapshot `report-{it,en}.txt`, `AlertsReportsTest`; `RiskScoreTest` (solo dati di test).
- **Frontend**: `core/alerts`, `core/reports`, `features/alerts/*`, `features/reports/*` con spec; `app.routes.ts`, `app.html`, `app.ts`, `home-detail.page.ts`, `i18n/{it,en}.json`, E2E (`mock-api.ts`, `dashboard.spec.ts`).
- **Docs**: 05, 19, 20, 21, 22 (nuovo), README, TECHNICAL_DECISIONS.

### Test
| Suite | Risultato |
|---|---|
| Backend suite completa | ✅ 196/196 |
| `AlertsReportsTest` (dedup, email, preferenze, risoluzioni, tenant, report) | ✅ 2/2 |
| `ReportRendererTest` (snapshot IT/EN, multipagina, testi regole) | ✅ 4/4 |
| Frontend spec pertinenti (alert, report, app) | ✅ 21/21 |
| Build di produzione | ✅ |
| E2E Playwright (desktop + mobile, contatore avvisi) | ✅ 6/6 |

### Problemi e note
- `RiskScoreTest` falliva se eseguito insieme a `SecurityAnalysisTest` (conflitto sull'ordine dei dati, preesistente): corretto cambiando solo i dati di test.
- Download del report: la transazione non può essere in sola lettura perché scrive l'audit.

### Limiti
- Niente push (M14) né ore di silenzio; nessun alert di sicurezza dell'account.
- Coda email e PDF nel database (nessun broker né object storage).
- Font standard: caratteri non latini nel PDF diventano `?`.
- Limite dei report provvisorio fino ai piani della M17.

## Milestone 12 — Riepilogo

**Obiettivo**: dashboard completa con il motore di rischio integrato, IT/EN, responsive, mappa di rete, E2E Playwright. Dettagli in [docs/21-DASHBOARD.md](docs/21-DASHBOARD.md), decisioni ADR-064 e ADR-065.

### Funzionalità implementate
- **Panoramica** (`/overview`, nuova pagina iniziale) con l'endpoint `GET /api/v1/overview`:
  - abitazioni dalla più a rischio;
  - per ognuna: ultimo punteggio, livello, giudizio, copertura, variazione, provvisorio, nota "Solo rilevamento", problemi per gravità, KEV, dispositivi, ultima scansione;
  - riepilogo complessivo;
  - i dati di sicurezza solo con `finding:read`.
- **Vulnerabilità note** (`/homes/:id/vulnerabilities`): CVE della casa con prima le KEV, poi per CVSS, filtri KEV e gravità, EPSS, qualità della corrispondenza, stato del finding, link NVD.
- **Mappa di rete** (`/homes/:id/network-map`):
  - logica, in SVG senza librerie: una stella per rete con il router al centro;
  - colori in base ai punti tolti all'ultimo punteggio, arco verso Internet per gli inoltri UPnP;
  - dettagli con mouse e tastiera, tabella equivalente.
- **Collegamenti e navigazione**: link dal dettaglio abitazione; voce "Panoramica" nel menu.
- **Responsive**: menu ☰ sotto 860 px; tabelle che scorrono nella scheda sotto 640 px.
- **Testi**: IT/EN.
- **E2E Playwright** sulla build di produzione con API `[MOCK]`, profili desktop e mobile, aggiunti alla CI.

### File
- **Backend (creati)**: `overview/OverviewController`, `OverviewService`, `OverviewRepository`.
- **Test backend (modificato)**: `RiskScoreTest`, con le verifiche della panoramica.
- **Frontend (creati)**:
  - `core/overview/overview.api.ts`;
  - `features/overview/*`, `features/vulnerabilities/*`, `features/network-map/*` (`network-layout.ts` e pagina), con spec;
  - `e2e/` (config, server statico, API `[MOCK]`, `dashboard.spec.ts`).
- **Frontend (modificati)**:
  - `app.html`, `app.ts`, `app.scss` (menu);
  - `styles.scss`;
  - `app.routes.ts` (pagina iniziale `/overview`);
  - `home-detail.page.ts` (link);
  - `findings.api.ts` (`homeVulnerabilities`);
  - `public/i18n/{it,en}.json`;
  - `package.json` e lock (`@playwright/test` 1.65.1, script `e2e`);
  - `.gitignore`.
- **Altri**: `.github/workflows` (passo E2E), docs 05, 20, 21, README, TECHNICAL_DECISIONS.

### Test
| Suite | Risultato |
|---|---|
| Backend `RiskScoreTest` (scenario M11 + panoramica) | ✅ 1/1 |
| Frontend unit (suite completa) | ✅ 106/106 (8 nuovi) |
| Build di produzione | ✅ (pagine nuove lazy: panoramica 2,6 kB, vulnerabilità 2,2 kB, mappa 4,8 kB trasferiti) |
| E2E Playwright (desktop + mobile) | ✅ 6/6 |

### Problemi e note
- **Nessun bug** nel codice esistente.
- **Correzioni durante lo sviluppo**:
  - server E2E: tipo MIME della radice;
  - mock CSRF;
  - mappa: etichette sovrapposte e arco di esposizione sopra il router, corretti dopo lo screenshot mobile.
- **i18n**: `it.json` ed `en.json` sono stati riscritti da uno script, quindi gli oggetti brevi prima su una riga ora sono su più righe. Il contenuto è invariato salvo le nuove chiavi.
- **npm 11**: segnala che gli script di installazione di esbuild e lmdb non sono stati eseguiti. Erano già installati: build e test funzionano.

### Limiti
- La mappa è logica: non mostra la topologia fisica e non distingue Wi-Fi e cavo.
- Gli E2E non usano il backend reale: la verifica completa è nella M18.
- Il client API è ancora scritto a mano e non generato da OpenAPI.
- Pagine di report, alert, integrazioni, assistente e abbonamento arrivano nelle rispettive milestone.

## Milestone 11 — Riepilogo

**Obiettivo**: punteggio di sicurezza spiegabile, copertura, snapshot e delta. Dettagli in [docs/20-RISK-ENGINE.md](docs/20-RISK-ENGINE.md), decisioni ADR-059…ADR-063.

### Funzionalità implementate
- **Punteggio 0–100** (`RiskEngine`, versione `2026.11-1`). Ogni finding toglie: gravità × tipo × affidabilità × criticità del dispositivo × esposizione UPnP × KEV. Un dispositivo toglie al massimo 45 punti; arrotondamento per difetto. Contano solo `OPEN`/`ACKNOWLEDGED`: falsi positivi e rischi accettati sono esclusi e mostrati a parte. Un dispositivo non identificato non è penalizzato.
- **Copertura**: dispositivi analizzati / visti, profilo, tecniche riuscite (ARP/ICMP/mDNS/SSDP), integrazione router. Sotto 0.6 il punteggio è limitato a 70 e provvisorio; sotto 0.8 il giudizio non è mai "Ottimo". Una scansione `DISCOVERY` non ha punteggio (`PORT_SCAN_REQUIRED`).
- **Snapshot** `risk_snapshots`, solo inserimenti:
  - `SCAN` alla chiusura della scansione, nella stessa transazione dell'analisi;
  - `TRIAGE` quando un triage cambia i finding conteggiati.
  - Contengono breakdown, dispositivi più a rischio e **delta** (variazione, nuovi finding, finding non più conteggiati con il motivo, nuovi dispositivi).
- **API**: `GET /homes/{id}/risk` (corrente + ultimo calcolato), `/risk/history`, `/vulnerabilities` (CVE della casa con KEV/EPSS). Permesso `finding:read`.
- **Dashboard**: pagina "Punteggio di sicurezza" con punteggio, livello, giudizio, avviso provvisorio, copertura, "Perché questo punteggio?", dispositivi più a rischio, cosa è cambiato e storico. Link dal dettaglio abitazione; IT/EN.

### File principali
- **Backend (creati)**: `V011__risk_engine.sql`; `risk/` (`RiskEngine`, `RiskRepository`, `RiskService`, `RiskController`); test `RiskEngineTest`, `RiskScoreTest`. **Modificati**: `AgentJobService` (calcolo dopo l'analisi), `FindingService` (ricalcolo dopo il triage, CVE della casa), `FindingRepository`, `FindingController`.
- **Frontend**: creati `core/risk/risk.api.ts` e `features/risk/risk.page.ts` (+spec); modificati `app.routes.ts`, `home-detail.page.ts`, `it.json`/`en.json`.
- **Documentazione**: nuovo `docs/20-RISK-ENGINE.md`; note in `docs/04`, `05`, `09`, `19`; ADR-059…063; README.

### Dipendenze
Nessuna nuova dipendenza.

### Test
- Backend nuovi:
  - `RiskEngineTest` (8): copertura bassa, dispositivo sconosciuto, limite per dispositivo, fattori, esclusioni, `DISCOVERY`, soglie;
  - `RiskScoreTest` (1 scenario via API): STANDARD → QUICK con delta, triage, `DISCOVERY`, storico, CVE della casa, altro tenant.
  - Totale 9/9, solo dati [MOCK].
- Regressione backend: `SecurityAnalysisTest`, `ScanWorkflowTest`, `PortScanningTest`, `NetworkDiscoveryTest`, `DeviceInventoryTest`, `DatabaseBaselineTest`, `TenantIsolationAndRbacTest`, `CrossTenantIsolationTest`, `HttpSurfaceTest`: 45/45.
- Frontend: `risk.page.spec`, `findings.page.spec` e `home-detail.page.spec`, 19/19; build di produzione OK.

### Limiti residui
- Pesi iniziali di docs/09, da tarare con dati reali (M18); doppio peso KEV voluto (ADR-062).
- Il punteggio cambia solo con una nuova scansione o un triage, non quando il catalogo KEV si aggiorna.
- Nessun alert sul cambio di punteggio (M13); pagina CVE della casa e network map con la dashboard completa (M12).

## Milestone 10 — Riepilogo

**Obiettivo**: analisi di sicurezza dei dispositivi, porte e servizi delle reti autorizzate: regole di finding versionate, ciclo di vita e deduplicazione, triage, sincronizzazione NVD/KEV/EPSS, matching CVE conservativo. Dettagli in [docs/19-SECURITY-ANALYSIS.md](docs/19-SECURITY-ANALYSIS.md), decisioni ADR-054…ADR-058.

### Funzionalità implementate
- **Analisi alla chiusura della scansione** (stessa transazione, dopo il fingerprinting), solo sui dispositivi visti dalla scansione; nessuna richiesta ai dispositivi.
- **14 regole** versionate (Telnet, FTP, login HTTP in chiaro, TLS obsoleto/scaduto, SMB1, mappature UPnP verso Internet, UPnP IGD, TR-069, RTSP, MQTT, SNMP, DNS ricorsivo, dispositivo non identificato) + **CVE** (`cve.version-match`, `cve.product-only`). Quattro tipi sempre distinti; gravità da CVSS, +1 livello per KEV.
- **Ciclo di vita**: deduplicazione per fingerprint, evidenze per scansione, riapertura se rilevato di nuovo; `RESOLVED` solo se la scansione ha coperto porta (profilo, versione lista, host non in pausa), dati UPnP o dispositivo. Triage `ACKNOWLEDGED`/`FALSE_POSITIVE`/`ACCEPTED_RISK` con motivazione obbligatoria e audit.
- **Vulnerability intelligence**: sync solo manuale da amministratore di piattaforma, in background, una alla volta; NVD limitata ai prodotti del dizionario CPE (paginata, mirror sostituito in una transazione), KEV, EPSS; HTTPS, limiti di dimensione/tempo, feed fallito che mantiene i dati, stato per feed, audit.
- **Matching conservativo**: dizionario curato (11 prodotti), nome intero per servizio, mai solo produttore; `CONFIRMED_VULNERABILITY` solo con banner, servizio confermato, versione esatta/nel range, senza condizioni di piattaforma; negate ignorate, AND → rischio potenziale; versione ignota → finding aggregato `PRODUCT_ONLY`.
- **API**: findings dell'abitazione con filtri, dettaglio con evidenze e CVE (KEV/EPSS), cambio stato, CVE, stato/avvio sync (piattaforma). Permessi `finding:read`/`finding:triage`.
- **Dashboard**: pagina "Problemi di sicurezza" (filtri, tipo spiegato, "Cosa significa"/"Cosa fare", evidenze, CVE, gestione con motivazione), link dal dettaglio abitazione; IT/EN.

### File principali
- **Backend (creati)**: `V010__security_analysis.sql`; `vulnintel/` (`Versions`, `CpeDictionary` + `cpe-dictionary.json`, `VulnerabilityRepository`, `FeedParsers`, `FeedDownloader`, `VulnerabilitySyncService`, `VulnerabilityMatcher`, `VulnerabilityController`); `findings/` (`FindingRule`, `FindingRules`, `PortLists` + `portlists.json`, `FindingRepository`, `SecurityAnalyzer`, `FindingService`, `FindingController`); test `VulnerabilityMatchingTest`, `VulnerabilitySyncTest`, `FindingRulesTest`, `SecurityAnalysisTest`. **Modificati**: `AgentJobService`, `AuditAction`, `Permissions`, `ShscProperties`, `application.yml`, `.env.example`, `docker-compose.yml`.
- **Frontend**: creati `core/findings/findings.api.ts`, `features/findings/findings.page.ts` (+spec); modificati `app.routes.ts`, `home-detail.page.ts`, `api-error.ts`, `it.json`/`en.json`.
- **Documentazione**: nuovo `docs/19-SECURITY-ANALYSIS.md`; note in `docs/04`, `05`, `09`; ADR-054…058; README.

### Dipendenze
Nessuna nuova dipendenza.

### Test
- Backend nuovi: `VulnerabilityMatchingTest` (6), `FindingRulesTest` (7), `SecurityAnalysisTest` (1, scenario completo), `VulnerabilitySyncTest` (2): 16/16, solo dati [MOCK] (CVE `CVE-2099-*`, feed su loopback).
- Regressione backend: `ScanWorkflowTest`, `PortScanningTest`, `NetworkDiscoveryTest`, `DeviceInventoryTest`, `DatabaseBaselineTest`, `OuiSyncTest`, `TenantIsolationAndRbacTest`, `CrossTenantIsolationTest`, `HttpSurfaceTest`, `AuthenticationFlowTest`: 54/54.
- Frontend: `findings.page.spec` + `home-detail.page.spec` 15/15; build di produzione OK.

### Limiti residui
- Dizionario CPE piccolo (prodotti fuori elenco: nessuna CVE); versioni dichiarate non verificate.
- Nessuna rianalisi delle scansioni passate, nessun alert "problema risolto" (M13), nessuna regola firmware (manca la fonte).
- Nessuna prova con feed NVD reali né con dispositivi reali (M18).
- Rischio, copertura, snapshot e delta: implementati nella M11.

## Milestone 9 — Riepilogo

**Obiettivo**: controllo delle porte e identificazione dei servizi dei dispositivi trovati, solo sulle reti autorizzate e solo con richieste di lettura: TCP connect con limiti, probe UDP di protocollo, banner/HTTP/TLS/RTSP OPTIONS/SMB NEGOTIATE/ONVIF/IPP. Dettagli in [docs/18-PORT-SCANNING.md](docs/18-PORT-SCANNING.md), decisioni ADR-049…ADR-053.

### Funzionalità implementate
- **Profili**: `QUICK` (40 TCP + 6 UDP) e `STANDARD` (301 TCP + 8 UDP), liste versionate incorporate nell'agent; `DEEP`/`CUSTOM` rimandati alla M17.
- **Agent** (`internal/portscan`): TCP connect con limiti firmati nel job (300/s e 256 in totale, 8 e 50/s per host, timeout 1,5 s, 1 retry), timeout → `FILTERED` mai `CLOSED`, pausa dell'host dopo 5 errori, ambito ricontrollato (rete autorizzata e collegata), annullamento immediato; fase `PORTS`.
- **UDP**: DNS, NTP mode 3, NBSTAT, SNMPv3 discovery senza community, SSDP, WS-Discovery/ONVIF (solo verso l'IP del dispositivo), mDNS, CoAP; porte UDP senza probe sicura mai contattate.
- **Servizi**: probabile vs confermato; banner passivi (nessun byte a SSH/Telnet/FTP/MQTT), HTTP `GET /` senza redirect, TLS (versioni, certificato), RTSP `OPTIONS`, SMB `NEGOTIATE` (dialetto, firma, SMB1), IPP `Get-Printer-Attributes`.
- **Backend**: `V009` (`open_ports`, `detected_services`, `detected_protocols` con RLS), ingestione validata e idempotente, scarto fuori ambito con audit, porte rifiutate per scansioni DISCOVERY, collegamento al dispositivo e protocolli rilevati nel fingerprinting, ruleset `2026.11-2` (13 nuove regole: ONVIF, RTSP, IPP, titoli/server HTTP, porte tipiche).
- **API**: `GET /scans/{id}/ports`; `services` nel dettaglio dispositivo.
- **Dashboard**: scelta del profilo, fase, porte aperte nella scansione e nel dettaglio dispositivo (contatori, servizi probabili/confermati, TLS, protocolli), dati dichiarati marcati come non verificati; IT/EN.

### File principali
- **Agent (creati)**: `internal/portscan/` (`portscan.go`, `lists.go`, `portlists.json`, `services.go`, `smb.go`, `ipp.go`, `udp.go`, `errno_unix.go`, `errno_windows.go` + 3 file di test [MOCK]), `internal/scan/ports.go` (+test). **Modificati**: `internal/scan/job.go`, `worker.go`, `internal/cloud/jobs.go`.
- **Backend (creati)**: `V009__port_scanning.sql`, `scans/PortRepository.java`, `scans/PortResponse.java`, `devices/DetectedProtocols.java`, test `PortScanningTest`. **Modificati**: `AgentJobController`, `AgentJobService`, `ScanRepository`, `ScanRequestService`, `ScanController`, `ScanQueryService`, `DeviceFingerprinter`, `DeviceService`, `DeviceController`, `HostEvidence`, `FieldResolver`, `rules.json`; test `ScanWorkflowTest` (profilo rifiutato ora `DEEP`), `NetworkDiscoveryTest` (metodo sconosciuto ora `EXPLOIT`).
- **Frontend**: creato `features/scans/port-table.component.ts`; modificati `scans.api.ts`, `devices.api.ts`, `scans.page.ts`, `devices.page.ts` (+spec), `it.json`/`en.json`.
- **Documentazione**: nuovo `docs/18-PORT-SCANNING.md`; note in `docs/04`, `05`, `08`, `15`, `17`; ADR-049…053; README.

### Dipendenze
Nessuna nuova dipendenza.

### Test
- Agent: `go vet` e `go test ./...` OK (14 test nuovi: servizi [MOCK] e test di policy su tutto ciò che l'agent invia).
- Backend: `PortScanningTest` (2) + regressione `ScanWorkflowTest`, `NetworkDiscoveryTest`, `DeviceInventoryTest`, `ClassificationRulesTest`, `FieldResolverTest`, `DatabaseBaselineTest`, `CrossTenantIsolationTest`, `AgentRuntimeTest`, `HttpSurfaceTest`, `RoleAuthorizationMatrixTest`: 58/58.
- Frontend: `scans.page.spec` + `devices.page.spec` 13/13; build di produzione OK.

### Limiti residui
- Prova su dispositivi reali rimandata alla M18: test solo con servizi [MOCK] su loopback.
- Timeout fisso (non adattivo), SMB 3.1.1 non offerto, test MQTT anonimo non implementato (ADR-012).
- Le porte aperte non sono ancora valutate come rischio: arriverà con la M10.

## Milestone 8 — Riepilogo

**Obiettivo**: inventario dei dispositivi con fingerprinting e classificazione spiegabili: registro OUI IEEE, regole con punteggi, affidabilità per campo, MAC randomizzati, classificazione manuale con storico, OS di base. Dettagli in [docs/17-DEVICE-FINGERPRINTING.md](docs/17-DEVICE-FINGERPRINTING.md), decisioni ADR-046…ADR-048.

### Funzionalità implementate
- **Inventario**: aggiornato alla chiusura di ogni scansione (anche upload tardivo) nella stessa transazione; un dispositivo per `(abitazione, MAC)` o per IP se manca il MAC; osservazioni collegate al dispositivo.
- **OUI**: registri MA-L/MA-M/MA-S, prefisso più lungo; sincronizzazione solo manuale da amministratore di piattaforma, tutto-o-niente, audit.
- **Classificazione**: 47 regole JSON versionate e validate all'avvio; serve un indizio forte o due medi indipendenti; indizi deboli da soli → "non identificato"; conflitti abbassano l'affidabilità, parità → non identificato; spiegazione salvata.
- **Affidabilità per campo** (IP, MAC, nome, produttore, modello, OS, tipo) con fonti, accordo/disaccordo e conflitti; OS da mDNS, SSDP, SNMP, NetBIOS, nome e TTL (il TTL da solo resta basso).
- **MAC randomizzati**: riconosciuti, OUI ignorato, "probabilmente lo stesso dispositivo" se il nome coincide.
- **Classificazione manuale**: mai sovrascritta, suggerimento se una scansione rileva altro con buona affidabilità; storico AUTO/MANUAL; audit.
- **Dashboard**: pagina "Dispositivi" dell'abitazione con elenco, dettaglio (campi, fonti, regole, storico), scelta della categoria; testi IT/EN.

### File principali
- **Backend (creati)**: `V008__device_fingerprinting.sql`; `fingerprint/rules.json`; package `com.shsc.devices` (`DeviceRepository`, `DeviceFingerprinter`, `DeviceService`, `DeviceController`), `devices.fingerprint` (`ClassificationRules`, `FieldResolver`, `HostEvidence`, `Signal`, `Confidence`, `DeviceCategory`, `Strength`), `devices.oui` (`OuiRegistryParser`, `OuiRepository`, `OuiSyncService`); test `ClassificationRulesTest`, `FieldResolverTest`, `OuiRegistryParserTest`, `OuiSyncTest`, `DeviceInventoryTest`.
- **Backend (modificati)**: `AgentJobService`, `Permissions`, `AuditAction`, `ShscProperties`, `application.yml`.
- **Frontend**: creati `core/devices/devices.api.ts`, `features/devices/devices.page.ts` (+spec); modificati `app.routes.ts`, `home-detail.page.ts`, `api-error.ts`, `it.json`/`en.json`.
- **Documentazione**: nuovo `docs/17-DEVICE-FINGERPRINTING.md`; note in `docs/04`, `05`, `07`; ADR-046…048; README; `.env.example` (`SHSC_OUI_SOURCES`, opzionale).

### Dipendenze
Nessuna nuova dipendenza.

### Test
- Backend: nuovi test unitari e d'integrazione (19) + regressione `ScanWorkflowTest`, `NetworkDiscoveryTest`, `DatabaseBaselineTest`: 41/41.
- Frontend: `devices.page.spec` + `home-detail.page.spec` 14/14; build di produzione OK.

### Limiti residui
- Registro OUI vuoto finché un amministratore non esegue la sincronizzazione (download reale da IEEE non eseguito nei test: solo server [MOCK] su loopback).
- Prova su LAN reale rimandata alla fase di test finale (M18), come per la M7.
- Regole limitate agli indizi della discovery; porte e servizi (M9) aggiungeranno indizi.

## Milestone 7 — Riepilogo

**Obiettivo**: discovery completa sulle sole reti autorizzate: ICMP, mDNS, SSDP/UPnP con anti-SSRF, UPnP IGD, NetBIOS, rDNS, IPv6 NDP, integrazioni router TR-064 e SNMP con credenziali del proprietario. Dettagli in [docs/16-NETWORK-DISCOVERY.md](docs/16-NETWORK-DISCOVERY.md), decisioni ADR-042…ADR-045.

### Funzionalità implementate
- **Agent**: pipeline parallela con collector che scarta ogni indirizzo fuori dagli obiettivi del job; sonde attive solo su reti collegate, multicast solo sull'interfaccia della rete autorizzata; avvisi espliciti per ogni tecnica non disponibile.
- **Anti-SSRF**: URL annunciati seguiti solo verso l'IP del dispositivo stesso (dialer vincolato, niente proxy/redirect, 3 s, 256 KB).
- **Router**: `shsc-agent router set-tr064|set-snmp|show|remove`; credenziali solo sull'agent (DPAPI/0600), community predefinite rifiutate, nessun retry dopo un rifiuto, router fuori ambito mai contattato; il backend vede solo i nomi delle integrazioni.
- **Backend**: `V007` (nuovi metodi, `hostname`, `details` jsonb ≤ 4096 B), validazione upload, dispositivi raggruppati per MAC con nome scelto per affidabilità ed evidenze per metodo.
- **Dashboard**: nome e fonte, indirizzi IPv4/IPv6 raggruppati, dati dichiarati marcati "non verificati", inoltri di porte UPnP evidenziati, integrazioni router nella diagnostica dell'agent; testi IT/EN.

### File principali
- **Agent (creati)**: `discovery/` `icmp_windows.go`, `icmp_unix.go`, `mdns.go`, `ssdp.go`, `httpsafe.go`, `names.go`, `ndp.go`, `ndp_unix.go`, `ndp_linux.go`, `ndp_windows.go`, `ndp_other.go`, `router.go`; `scan/router.go`; `cli/router.go`; test `protocols_test.go`, `ndp_linux_test.go`, `cli/router_test.go`.
- **Agent (modificati)**: `discovery.go`, `discovery_test.go`, `arp_linux.go`, `arp_windows.go`, `scan/worker.go`, `cloud/jobs.go`, `identity/identity.go`, `capabilities/capabilities.go`, `cli/cli.go`, `cli/agent.go`, `go.mod`/`go.sum`.
- **Backend**: `V007__network_discovery.sql`; `AgentJobController`, `AgentJobService`, `ScanRepository`, `ScanController`, `AgentRuntimeController`; test `NetworkDiscoveryTest`.
- **Frontend**: `scans.api.ts`, `scans.page.ts` (+spec), `homes.api.ts`, `home-detail.page.ts`, `it.json`/`en.json`.
- **Documentazione**: nuovo `docs/16-NETWORK-DISCOVERY.md`; note in `docs/03`, `04`, `05`, `07`; ADR-042…045; README.

### Dipendenze
`golang.org/x/net` v0.62.0 (BSD-3) e `github.com/gosnmp/gosnmp` v1.47.0 (BSD-2), gratuite: vedi ADR-042 e ADR-043.

### Test
- Agent: `go vet` linux/windows/darwin e `go test ./...` verdi; responder [MOCK] su loopback (mDNS, SSDP+IGD, NetBIOS, TR-064 digest), casi negativi anti-SSRF, pipeline con indirizzi fuori ambito; build dei 7 binari.
- Backend: `NetworkDiscoveryTest` + regressione `ScanWorkflowTest`, `AgentRuntimeTest` (20/20).
- Frontend: 80/80.

### Limiti residui
- **Prova manuale su LAN reale autorizzata non eseguita** (qui l'E2E è consentito solo sulla rete virtuale WSL): da fare dal proprietario.
- mDNS: le risposte che i dispositivi inviano solo in multicast non sono viste. macOS: niente ARP attivo né tabella IPv6. Windows: IPv6 solo dalla tabella dei vicini.
- SNMP verificato con un router v2c **[MOCK]** su loopback (lettura tabella ARP; community errata: un solo invio + 1 ritrasmissione, nessuna altra community); SNMPv3 senza mock (verificata solo la mappatura degli errori USM). TR-064 solo su HTTP con digest.
- Prova su LAN reale: procedura in [docs/16 §8](docs/16-NETWORK-DISCOVERY.md), da eseguire dal proprietario.
- Raggruppamento per MAC è un'indicazione: inventario, OUI e classificazione sono della M8.

## Milestone 6 — Riepilogo

**Obiettivo**: workflow delle scansioni manuali: macchina a stati, job firmati con long polling, progress e annullamento, upload a lotti idempotenti, validazione dell'ambito, reaper, UI minima "Avvia scansione" con stato, discovery minima (interfacce + ARP). Dettagli in [docs/15-MANUAL-SCANS.md](docs/15-MANUAL-SCANS.md), decisioni ADR-037…ADR-041.

### Funzionalità implementate
- **Macchina a stati** PENDING → QUEUED → RUNNING → COMPLETED / COMPLETED_WITH_WARNINGS / FAILED / CANCELLED, con lock ottimistico, eventi in `scan_events`, una sola scansione attiva per abitazione e `trigger = MANUAL` imposto dal database.
- **Richiesta** con `Idempotency-Key`. Controlli: permesso, rete autorizzata, agent online, nessuna scansione attiva, limite FREE di 10 scansioni per abitazione in 24 h. Registrata in audit.
- **Job firmati Ed25519**: chiave pubblica fissata nell'agent all'enrollment, oppure una volta dalla sessione per gli agent già registrati. Il job viene ritirato con long polling (≤ 25 s) su thread virtuali, con risveglio immediato.
- **Esecuzione**: ack, progress con lease di 2 min, annullamento (immediato in coda, cooperativo in corso), reaper ogni 30 s (AGENT_OFFLINE / AGENT_LOST / TIMEOUT); la revoca dell'agent chiude le sue scansioni.
- **Risultati**: lotti da 500 idempotenti, verifica dei lotti alla chiusura, IP fuori ambito scartati e registrati in audit, upload tardivo accettato entro 24 h (`LATE_UPLOAD`). Sull'agent i risultati passano dalla coda SQLite.
- **Discovery**: solo sottoreti autorizzate collegate direttamente all'agent, solo IPv4.
  - Windows: `SendARP`.
  - Linux: ARP raw con `CAP_NET_RAW`, altrimenti tabella dei vicini.
  - Avvisi tradotti.
- **Dashboard**: pagina "Scansioni" dell'abitazione con avvio, stato e percentuale (aggiornamento ogni 3 s), annullamento, storico, dispositivi trovati con la nota "non indica vulnerabilità". Testi IT/EN; limite del piano in Organizzazione.

### File principali
- **Creati (backend)**: `V006__manual_scans.sql`; package `com.shsc.scans` con:
  - JobSigner, ScanRepository, ScanStateMachine, ScanJobNotifier;
  - ScanRequestService, ScanQueryService, ScanController;
  - AgentJobService, AgentJobController, ScanReaper;
  - test `ScanWorkflowTest`.
- **Modificati (backend)**: ShscProperties, application.yml, PlanLimits, TenancyController, AuditAction, Permissions, NetworkRange (`contains`), AgentController, AgentManagementService, PostgresTestContainer.
- **Creati (agent)**: `internal/scan` (job, worker), `internal/discovery` (piano, ARP Windows/Linux/altro), `internal/cloud/jobs.go`; test `job_test.go`, `discovery_test.go`.
- **Modificati (agent)**: `cloud/client.go`, `identity.go`, `agentauth.go`, `runner.go` (attività in background), `cli/agent.go`.
- **Frontend**:
  - creati `core/scans/scans.api.ts` e `features/scans/scans.page.ts` (+spec);
  - modificati `app.routes.ts`, `api-error.ts`, `home-detail.page.ts` (link), `tenancy.api.ts`, `organization.page.ts` (+spec), `it.json`/`en.json`.
- **Infrastruttura e documentazione**:
  - `generate-job-signing-key.sh`, `docker-compose.yml`, `.env.example`;
  - nuovo `docs/15-MANUAL-SCANS.md`; note in `docs/02`–`05`; ADR-037…041; README.

### Dipendenze
Nessuna nuova: Ed25519, thread virtuali e chiamate di sistema ARP sono nelle librerie standard di Java e Go o in `golang.org/x/sys`, già presente.

### Test
- **Backend 143/143** (regressione M2–M5 inclusa). `ScanWorkflowTest` (12) copre:
  - percorso completo con verifica della firma;
  - annullamento in coda e in corso;
  - agent offline, lease scaduto con upload tardivo e rifiuto oltre 24 h;
  - timeout e revoca;
  - lotti mancanti, idempotenza, limite del piano, ruoli e tenant;
  - long polling e vincoli del database.
- **Agent Go**: gofmt e vet (Linux, Windows, macOS) puliti, tutti i test verdi, inclusi i nuovi su verifica del job (firma, manomissione, agent, scadenza, reti pubbliche, limiti) e piano e ambito della discovery. Cross-compile dei 7 binari con `build-agent.sh` OK.
- **Frontend 79/79** (4 nuovi test della pagina Scansioni); build OK.
- **End-to-end** sullo stack dev (17/11/2026) con il binario Windows reale e un tenant di test. Unica rete autorizzata la rete **virtuale** WSL di questo PC (`172.20.204.0/22`), nessuna LAN fisica.
  - Clic su "Avvia scansione" → job ritirato dall'agent in meno di 1 s → avanzamento visibile → `COMPLETED` in 3 min 23 s → in dashboard la VM WSL (172.20.204.217, MAC Hyper-V, metodo ARP).
  - Seconda scansione annullata dalla dashboard → `CANCELLED` entro un ciclo di progress.
  - Nessun errore nel log dell'agent.

### Problemi riscontrati e risolti
- Errori di compilazione minori (import mancanti) e formattazione gofmt, corretti.
- Lo script delle traduzioni aveva espanso su più righe alcuni oggetti brevi delle traduzioni: ripristinato il formato originale, le modifiche ai file di lingua sono solo aggiunte.

### Limiti noti
- Su Windows la discovery di una /22 dura circa 3–4 minuti: `SendARP` attende circa 1 s per ogni indirizzo che non risponde. Il limite di 15 minuti copre fino a /22.
- ARP non è disponibile su macOS (avviso `ARP_UNAVAILABLE`); IPv6 non è analizzato. ICMP, mDNS e SSDP arrivano con la milestone della discovery.
- Il test end-to-end usa un edge HTTP temporaneo su `127.0.0.1:8090` (rimosso al termine), perché il browser integrato rifiuta il certificato self-signed; HTTPS è verificato con curl e con l'agent.
- La chiave `SHSC_JOB_SIGNING_KEY` è stata aggiunta al `.env` locale (non versionato). In produzione va generata con lo script; se la si ruota, gli agent vanno registrati di nuovo.

## Milestone 5 — Riepilogo

**Obiettivo**: binario Go come servizio (Windows/Linux/macOS), enrollment, chiavi Ed25519, token agent, heartbeat, revoca, coda SQLite, autodiagnosi capabilities; limite agent per abitazione (dalla M4). Dettagli in [docs/14-AGENT-RUNTIME.md](docs/14-AGENT-RUNTIME.md), decisioni ADR-031…ADR-036.

### Funzionalità implementate
- **Comandi agent**: `run` (ciclo dell'agent), `service install|uninstall|start|stop|status`, `diagnose [--json] [--offline]`; codici di uscita 3 (revocato) e 4 (non registrato).
- **Servizio di sistema**: Windows (LocalService, avvio ritardato, ripristino dopo errori), systemd (utente `shsc`, solo `CAP_NET_RAW`, sandboxing), launchd. Un agent revocato non viene riavviato. Controlli sul percorso dell'eseguibile.
- **Chiavi**: Windows con DPAPI machine scope e ACL esplicita sulla cartella; Linux/macOS `0600`/`0700`. All'enrollment la CA indicata viene copiata nella cartella di stato con percorso assoluto.
- **Heartbeat** ogni 25 s (deciso dal server) con versione, uptime, capabilities, interfacce (solo se cambiate), profondità coda, ultimo errore. Connettività ONLINE / STALE / OFFLINE / NEVER_CONNECTED / REVOKED.
- **Revoca**: l'agent la scopre al primo heartbeat (≤ 25 s), svuota la coda, cancella le chiavi, archivia l'identità ed esce.
- **Coda SQLite** locale per gli eventi: idempotente, persistente ai riavvii, tetto 200 MB con evento `QUEUE_OVERFLOW`; backoff esponenziale con jitter 1 s → 5 min.
- **Eventi**: `AGENT_STARTED`, `AGENT_STOPPED`, `CAPABILITIES_CHANGED`, `CONNECTION_RESTORED`, `QUEUE_OVERFLOW`; backend idempotente, ultimi 500 per agent.
- **Autodiagnosi** di ARP/ICMP/privilegi/interfacce senza inviare pacchetti (Linux `AF_PACKET`/ICMP/`/proc/net/arp`, macOS BPF/ICMP datagram, Windows iphlpapi).
- **Limite FREE**: 2 agent attivi per abitazione (token e enrollment), revocati esclusi.
- **Dashboard**: stato di connettività, pannello "Diagnostica" (capabilities, avvisi, interfacce, ultimo errore, eventi), suggerimento `service install` dopo l'enrollment, riga del piano in Organizzazione. Testi IT/EN.

### File principali
- **Creati (agent)**: `internal/queue`, `internal/capabilities` (probe per OS), `internal/runner`, `internal/service` (systemd, launchd, Windows), `internal/logging`, `internal/identity/{protect,owner}_*.go`, `internal/cli/agent.go`, `go.sum`, relativi test.
- **Modificati (agent)**: `identity.go`, `agentauth.go`, `cloud/client.go`, `cli/cli.go`, `go.mod`.
- **Creati (backend)**: `V005__agent_runtime.sql`, `agents/runtime/AgentRuntimeService.java` e `AgentRuntimeController.java`; test `AgentRuntimeTest`, `support/TestAgents`.
- **Modificati (backend)**: AgentRepository, AgentManagementController/Service, AgentAuthService, PlanLimits, TenancyController, ShscProperties, application.yml.
- **Modificati (frontend)**: homes.api, tenancy.api, home-detail.page (+spec), organization.page (+spec), styles.scss, it.json/en.json.
- **Documentazione**: nuovo `docs/14-AGENT-RUNTIME.md`; aggiornati `docs/03`, `docs/04`, `docs/05`, `TECHNICAL_DECISIONS.md` (ADR-031…036), README.

### Dipendenze (open source, gratuite)
- `modernc.org/sqlite` v1.62.0 (BSD-3): SQLite in Go puro, nessun cgo (ADR-031).
- `golang.org/x/sys` v0.50.0 (BSD-3): servizi Windows, DPAPI, ACL, iphlpapi, capabilities Linux (ADR-032).

### Test
- Agent Go: gofmt e vet (Linux, Windows, macOS) puliti; 55 test, tutti verdi su Linux (container) e su Windows (binari di test eseguiti sull'host: DPAPI, ACL, iphlpapi, servizio); cross-compile dei 7 binari con `build-agent.sh` OK.
- Backend: **131/131** (Testcontainers, PostgreSQL 18 con RLS), regressione M2–M4 inclusa; nuovo `AgentRuntimeTest` (7 test).
- Frontend: **75/75**.
- End-to-end sullo stack dev (17/11/2026) con il binario Windows reale, tenant di test: enrollment, `diagnose` (ARP/ICMP `os_api`, interfacce), `run` da un'altra cartella → ONLINE con capabilities, interfacce ed evento `AGENT_STARTED`; nginx fermato per 154 s → 8 tentativi falliti con backoff, ripresa automatica ed evento `CONNECTION_RESTORED`, `lastError` azzerato al heartbeat successivo; revoca da API → agent fermo con codice 3 dopo **10 s**, chiavi cancellate, identità archiviata.

### Problemi riscontrati e risolti
- File di piattaforma del servizio compilati su tutti gli OS (nomi senza suffisso) → rinominati `service_<os>.go`.
- Evento `AGENT_STARTED` perso con un arresto rapido → scrittura in coda con contesto non annullabile.
- launchd avrebbe riavviato un agent revocato → `KeepAlive` legato a `agent.json`.
- `diagnose` / `service status` negati senza privilegi su Windows → accesso al Service Control Manager in sola lettura.
- Percorso relativo di `--ca-file` salvato nell'identità: il servizio falliva da un'altra cartella → copia della CA nella cartella di stato con percorso assoluto (test di regressione).

### Limiti noti
- `service install` non eseguito su un PC reale (richiede amministratore e modifica il sistema); systemd e launchd verificati solo tramite i file generati; nessuna esecuzione su un host Linux o macOS reale.
- Le interfacce riportate non diventano ancora reti candidate; i job di scansione arrivano con la M6.
- L'alert "agent offline" è rimandato alla milestone degli alert (M13); aggiornamenti firmati rimandati.
- Gli indirizzi IPv6 globali delle interfacce sono dati personali: visibili solo agli utenti del tenant con permesso `agent:read`.
- Le chiavi su macOS sono in un file `0600` di root, non nel Keychain (ADR-034).

## Milestone 4 — Riepilogo

**Obiettivo**: CRUD utenti/ruoli, organizzazioni, clienti, abitazioni, reti; limiti del piano FREE. Dettagli in [docs/13-USERS-ORGANIZATIONS-NETWORKS.md](docs/13-USERS-ORGANIZATIONS-NETWORKS.md), decisioni ADR-024…ADR-030.

### Funzionalità implementate
- **Utenti**: invito con ruolo e ambito (token INVITATION, 7 giorni, link `/accept-invitation#token=`), attivazione con password, rinvio invito, disattivazione (revoca immediata di sessioni e token; vietata su sé stessi e sull'ultimo amministratore), riattivazione. Nessuna cancellazione fisica.
- **Ruoli**: nuovo ambito `CUSTOMER` (vale per il cliente e tutte le sue abitazioni); stesse regole anti-escalation della M3.
- **Organizzazione**: lettura e modifica (PUT) dei dati aziendali, P.IVA normalizzata; piano e uso rispetto ai limiti.
- **Clienti** (solo tenant BUSINESS): creazione, modifica, archiviazione (bloccata se ha abitazioni attive).
- **Abitazioni**: cliente facoltativo, indirizzo, fuso orario; modifica e archiviazione (bloccata con agent attivi); filtro per cliente.
- **Reti**: solo intervalli privati/locali, dimensione minima /22 (IPv4) e /64 (IPv6), nessuna sovrapposizione, CIDR immutabile; doppia barriera applicazione + `CHECK` nel DB. **Autorizzazione** con attestazione versionata esplicita (mai preselezionata), storico e revoca. Nessuna scansione avviata.
- **Limiti FREE** (sotto lock `FOR UPDATE` sul tenant): 2 abitazioni, 3 utenti, 2 clienti, 4 reti per abitazione → 409 `PLAN_LIMIT_REACHED`.
- **Audit** di tutte le operazioni nuove.
- **Dashboard**: pagine Utenti, Clienti, Organizzazione, Attiva account; Abitazioni con clienti; dettaglio abitazione con modifica, archiviazione e sezione Reti. Testi IT/EN.

### File principali
- **Creati (backend)**: `V004__organizations_customers_networks.sql`, `tenancy/` (PlanLimits, TenancyService, TenancyController), `customers/*`, `networks/*` (NetworkRange, NetworkRepository, NetworkService, NetworkController), `identity/user/UserService.java`; test `UserManagementTest`, `CustomersHomesAndPlanTest`, `NetworkManagementTest`, `NetworkRangeTest`, `RoleAuthorizationMatrixTest`.
- **Modificati (backend)**: AccessPolicy, RoleAssignment, Permissions, RoleService, RoleAssignmentRepository, UserController, UserRepository, ActionTokenRepository, HomeRepository/Service/Controller, TenantRepository, AuditAction, AccountMailer, AuthenticationService, AuthController, SecurityConfig, ShscProperties, application.yml, messaggi i18n.
- **Creati (frontend)**: `core/users`, `core/customers`, `core/tenancy` (API), pagine `accept-invitation`, `users`, `customers`, `organization`, helper `testing/page-setup.ts`, relative spec.
- **Modificati (frontend)**: auth.models, auth.service, api-error, homes.api, homes.page, home-detail.page, app.routes, app.html/app.ts, it.json/en.json.
- **Documentazione**: nuovo `docs/13-USERS-ORGANIZATIONS-NETWORKS.md`; aggiornati `docs/05-API.md`, `docs/04-DATABASE.md`, `TECHNICAL_DECISIONS.md` (ADR-024…030), README.

### Dipendenze
Nessuna nuova dipendenza.

### Test
- Backend: **124/124** (Testcontainers, PostgreSQL 18 con RLS), regressione M2/M3 inclusa; nuovo `CrossTenantIsolationTest` (IDOR con ORGANIZATION_ADMIN e SUPER_ADMIN di un altro tenant).
- Frontend: **73/73**; build di produzione OK.
- Agent Go: gofmt, vet, `go test -race` OK (19 test).
- Stack dev: migrazione V004 applicata sul DB esistente; smoke test (401 senza autenticazione, `/accept-invitation` 200, accettazione invito senza CSRF 403).
- Verifica finale API sullo stack dev (17/11/2026): due tenant B2B reali, 33/33 controlli: 18 tentativi IDOR → 404, ID estranei nel corpo → 400, elenchi e audit senza dati altrui, dati della vittima invariati.

### Problemi riscontrati e risolti
- Text block Java: lo stripping degli spazi produceva SQL come `RETURNINGid` / `updated_atFROM` in HomeRepository e CustomerRepository → spazio esplicito.
- Spec frontend: richiesta token non presente per utenti senza `agent:enroll`; input di test non validi → corretti.

### Limiti noti
- Limite agent per abitazione rimandato alla M5.
- Le assegnazioni di ruolo rifiutate non sono registrate in audit.
- Le email sono uniche a livello globale: un amministratore che invita un indirizzo già registrato in un altro tenant riceve `EMAIL_ALREADY_REGISTERED`, quindi può dedurre che l'indirizzo esiste (solo amministratori, endpoint limitato in frequenza).
- Tenant di sviluppo esistenti possono superare i limiti FREE (i limiti valgono solo per le nuove creazioni).
- Gateway e interfaccia delle reti arriveranno con le reti rilevate dall'agent.
- Verifica della UI M4 nel browser (17/11/2026, Chrome locale dell'utente con certificato dev accettato, sessione B2C esistente, solo lettura): pagine Abitazioni, dettaglio con Reti e Agent, Organizzazione con piano e uso, Account e sessioni, Stato sistema OK; menu senza Utenti e Clienti per un ruolo cliente; `/users` aperto da URL mostra "Non hai i permessi"; l'ID di abitazione di un altro tenant nell'URL mostra "Elemento non trovato"; nessun errore in console. Le azioni di gestione B2B (invito, ruoli, clienti) sono coperte dai test di integrazione e dalla verifica API, non ripetute nella UI per non disconnettere la sessione dell'utente.

## Milestone 3 — Riepilogo
Documentazione completa: [docs/12-AUTHENTICATION.md](docs/12-AUTHENTICATION.md). Decisioni: ADR-005, ADR-017…ADR-023.

### Funzionalità completate
- **Utenti**:
  - registrazione B2C/B2B con verifica email e login;
  - logout, recupero e reset password (token monouso via email), cambio password;
  - sessioni per dispositivo: elenco, revoca singola, "esci dagli altri dispositivi", "esci ovunque".
- **Token**:
  - JWT ES256 di 15 min, solo in memoria nel browser;
  - refresh opaco in cookie HttpOnly/Secure/SameSite=Strict, ruotato a ogni uso, solo hash in DB;
  - riuso di un refresh già ruotato → sessione revocata e audit;
  - CSRF double-submit.
- **Password**: Argon2id, policy 12–128 caratteri con lista di password comuni, throttling per account e per IP con blocco progressivo, messaggi che non rivelano se un'email esiste.
- **RBAC**:
  - ruoli SUPER_ADMIN, ORGANIZATION_ADMIN, TECHNICIAN, CUSTOMER, READ_ONLY;
  - permessi dal DB con scope tenant, organizzazione o casa, sempre verificati dal backend;
  - un ID di un altro tenant restituisce 404;
  - prevenzione delle escalation; l'ultimo amministratore non è rimovibile.
- **Multi-tenancy**: RLS PostgreSQL su tutte le tabelle tenant, contesto tenant per transazione, lookup pre-autenticazione tramite funzioni `SECURITY DEFINER`.
- **Agent**:
  - enrollment con token monouso di 30 min e identità Ed25519 per agent;
  - asserzioni firmate scambiate con token opachi di 10 min, controllo dell'associazione agent–casa;
  - rotazione delle credenziali e revoca immediata.
  - CLI Go: `enroll`, `status`, `rotate-key` (solo HTTPS, `--ca-file` per lo sviluppo).
- **Audit**: log append-only di login riusciti e falliti, logout, riuso di token, revoca di sessioni, cambi di ruolo, password ed eventi agent; consultabile da `GET /api/v1/audit-logs`.
- **Frontend**: login, registrazione, verifica email, password dimenticata e reset, account e sessioni, case, dettaglio casa con codice di enrollment e gestione agent; IT/EN.
- **Configurazione**: tutti i segreti da variabili d'ambiente; script `generate-jwt-key.sh`; `.env.example` e `docker-compose.yml` aggiornati (SMTP Mailpit in sviluppo).

### File principali creati
- **Database**: `database/migrations/V002__identity_access.sql`, `V003__agent_authentication.sql`.
- **Backend** (`backend/spring-boot-api/src/main/java/com/shsc/`):
  - `shared/{config,persistence,crypto,web}`, `audit/`;
  - `identity/{access,authentication,mail,password,role,session,token,user}`;
  - `tenancy/`, `homes/`, `agents/{auth,management}`, `security/`;
  - risorse `i18n/messages*.properties`, `security/common-passwords.txt`.
- **Test backend**: `support/` (`ApiClient`, `Mailbox`, `TestAccounts`, `IntegrationTest`); `identity/*Test`, `agents/AgentAuthenticationTest`.
- **Agent Go**: `internal/{identity,assertion,cloud,agentauth}` + test.
- **Frontend**:
  - `core/auth/*`, `core/api/api-error.ts`, `core/homes/homes.api.ts`;
  - `features/auth/*`, `features/account/*`, `features/homes/*`;
  - `core/i18n/localized-date.pipe.ts` (date nella lingua dell'interfaccia);
  - `testing/{auth-fixtures,http}.ts` e spec.
- **Infrastruttura e documentazione**: `infrastructure/scripts/generate-jwt-key.sh`, `docs/12-AUTHENTICATION.md`.

### File modificati
`pom.xml`, `application.yml`, `ShscApiApplication.java`, `PostgresTestContainer.java`, `DatabaseBaselineTest.java`, `HttpSurfaceTest.java`, `infrastructure/nginx/conf.d/default.conf` (limite auth 30 r/min, burst 20), `.env.example`, `docker-compose.yml`, `internal/cli/cli.go`, `app.{ts,html,scss,routes.ts,config.ts,spec.ts}`, `styles.scss`, `public/i18n/{it,en}.json`, `features/homes/{homes,home-detail}.page.ts`, `features/account/account.page.ts`, `README.md`, `TECHNICAL_DECISIONS.md`, `docs/05-API.md`, `PROJECT_STATUS.md`.

### Dipendenze introdotte (open source, nessun costo)
- `spring-boot-starter-jdbc` al posto di `data-jpa` (ADR-017).
- `spring-boot-starter-security`, `spring-boot-starter-security-oauth2-resource-server` (porta con sé Nimbus JOSE), `spring-boot-starter-mail` — Apache 2.0.
- `org.bouncycastle:bcprov-jdk18on` 1.86 — MIT (Argon2).
- Test: `spring-boot-starter-jdbc-test`, `spring-boot-starter-security-test`.

Agent e frontend: **nessuna nuova dipendenza** (libreria standard Go con `crypto/ed25519`; Angular già presente). Nessun servizio a pagamento.

### Test eseguiti e risultati
| Suite | Risultato |
|---|---|
| Backend (Testcontainers PostgreSQL 18) | ✅ **66/66** |
| Frontend (Vitest) | ✅ **51/51** (43 + 8 aggiunti dopo la verifica nel browser); build di produzione OK (≈ 87 kB iniziali trasferiti, pagine lazy) |
| Agent Go (`go vet`, `go test -race`) | ✅ 19 test; cross-compile di 7 target |
| End-to-end sullo stack Docker (HTTPS + Mailpit + binario agent Windows reale) | ✅ vedi `docs/12-AUTHENTICATION.md` §8 |
| Verifica dell'interfaccia nel browser (7 aree: login, refresh e scadenza, logout, pagine protette, ruoli, isolamento tra organizzazioni, enrollment e revoca agent) | ✅ vedi `docs/12-AUTHENTICATION.md` §8.1 |
| gitleaks | ✅ nessun segreto nei file tracciabili (segnalato solo `.env` locale, escluso da git); le password fittizie dei test sono marcate riga per riga con `gitleaks:allow` |

### Problemi riscontrati e risolti
1. `NimbusJwtDecoder.withPublicKey` accetta solo RSA: il decoder ES256 è costruito con `DefaultJWTProcessor`.
2. L'health check della posta marcava l'API come DOWN se l'SMTP non rispondeva: disattivato (l'invio è asincrono e non blocca le richieste).
3. Le funzioni di lookup restituiscono NULL per token sconosciuti → HTTP 500: gestito, ora la risposta è 401.
4. **Trovato con la verifica end-to-end**: ogni richiesta Bearer cancellava il cookie CSRF e il refresh successivo falliva con 403. Corretto (ADR-020) e coperto da un test di regressione.
5. **Trovato nella verifica nel browser**: le date erano sempre in formato inglese (`Nov 16, 2026`, `4:34 PM`) anche con l'interfaccia in italiano, perché `DatePipe` usa il `LOCALE_ID` fisso `en-US`. Ora la pipe `appDate` segue la lingua scelta (`16 nov 2026`, `16:43`) e cambia insieme alla lingua.
6. **Trovato nella verifica nel browser**: la revoca di un agent partiva con un solo clic, ma è irreversibile (serve un nuovo enrollment). Ora c'è una conferma in due passaggi, con la possibilità di annullare.
7. **Trovato nella verifica nel browser**: un utente senza permessi vedeva insieme "Non hai i permessi" e "Nessuna abitazione. Creane una". Ora compare solo l'errore; chi non può creare case vede "Nessuna abitazione disponibile per il tuo account".

### Limiti / non verificato
- MFA e OIDC predisposti ma non implementati.
- Su Windows i file di identità dell'agent ereditano le ACL della cartella; l'hardening con ACL dedicate è previsto con l'installer o servizio.
- Verifica nel browser fatta tramite un nginx temporaneo in HTTP su `127.0.0.1:8090`, fuori dal repository, perché il browser integrato non accetta il certificato self-signed. Il percorso HTTPS reale è verificato con curl e con l'agent. Il pannello del browser era nascosto: i campi sono stati compilati con `form_input` e i form inviati con eventi DOM (`requestSubmit`/`click`) invece di clic del mouse; il rendering visivo (screenshot) non è stato verificato.
- Non esiste ancora un'API di invito utenti: per la prova dei ruoli tecnico e sola lettura sono stati inseriti nel DB, come nei test di integrazione. I ruoli invece sono stati assegnati tramite API.
- I tentativi di assegnazione di ruolo rifiutati (403) non vengono registrati nell'audit; vengono registrati solo quelli riusciti.
- La CI GitHub non è ancora stata eseguita (nessun remote).

## Milestone 2 — Riepilogo

### Funzionalità completate
- Progetto spostato su Desktop e repository git dedicato (ADR-001).
- **Backend** Spring Boot 4.1.2 / Java 21: configurazione solo da environment, Problem Details (RFC 9457), health/readiness/liveness, actuator ristretto, OpenAPI disattivabile, log JSON strutturati, immagine Docker non-root con healthcheck.
- **Database** PostgreSQL 18: ruoli separati migrator/app senza BYPASSRLS (ADR-014), schema `shsc`, Flyway con migrazioni in `database/migrations`, V001 (estensioni citext/pg_trgm + `current_tenant_id()` per la RLS).
- **Frontend** Angular 22: shell con selettore lingua IT/EN (Transloco), pagina "Stato del sistema" che interroga il backend reale, tema chiaro/scuro.
- **Agent** Go 1.27: CLI `version` / `help`, metadati di build iniettati, cross-compile statico per Windows/Linux/macOS (amd64/arm64/arm).
- **Infrastruttura**: `docker-compose.yml` (postgres, backend, nginx; mailpit con profilo `dev`), Nginx con TLS 1.2/1.3, redirect HTTP→HTTPS, header di sicurezza e CSP, rate limit, rete DB interna, certificato self-signed solo in dev; `.env.example`; script di backup con retention; script di test/build containerizzati.
- **CI** GitHub Actions: backend, frontend, agent, Compose/Nginx, gitleaks.

### File creati
`.gitattributes`, `.dockerignore`, `.env.example`, `docker-compose.yml`, `.github/workflows/ci.yml`,
`backend/spring-boot-api/` (pom.xml, Maven Wrapper, Dockerfile, `ShscApiApplication.java`, `application.yml`, test `DatabaseBaselineTest`, `HttpSurfaceTest`, `support/PostgresTestContainer`),
`database/migrations/V001__baseline.sql`,
`frontend/angular-dashboard/` (progetto Angular, `core/i18n/*`, `core/system/*`, `features/system-status/*`, `testing/transloco-testing.ts`, `public/i18n/{it,en}.json`, spec),
`agent/go-security-agent/` (`go.mod`, `cmd/shsc-agent/main.go`, `internal/buildinfo`, `internal/cli` + test),
`infrastructure/docker/postgres/init/01-roles.sh`, `infrastructure/nginx/` (Dockerfile, `conf.d/default.conf`, snippets, script certificato),
`infrastructure/scripts/` (`test-backend.sh`, `build-agent.sh`, `backup-db.sh`).

### File modificati
`.gitignore`, `PROJECT_STATUS.md`, `TECHNICAL_DECISIONS.md` (ADR aggiornati + ADR-014/015/016), `README.md`, `docs/01-ARCHITECTURE.md`.

### Dipendenze introdotte (tutte open source, nessun costo)
Spring Boot starters (webmvc, validation, actuator, data-jpa, flyway), Flyway PostgreSQL, driver PostgreSQL, springdoc-openapi 3.2.0, Testcontainers (test) — Apache 2.0 / BSD.
Angular 22 (generato da CLI), `@jsverse/transloco` 8.4.0 (MIT) per l'i18n runtime IT/EN.
Agent: **nessuna dipendenza esterna** (solo libreria standard).
Immagini Docker ufficiali: postgres, maven/temurin, node, golang, nginx, mailpit (dev), gitleaks (CI).

### Test eseguiti e risultati
| Suite | Risultato |
|---|---|
| Backend (`test-backend.sh`, Testcontainers PG18) | ✅ 12/12 — migrazione applicata, ruolo app senza superuser/BYPASSRLS/DDL, history di proprietà del migrator, contesto tenant per transazione, estensioni; health UP senza dettagli, probe, endpoint actuator sensibili 404, docs disattivate, 404 in Problem Details |
| Frontend (Vitest) | ✅ 14/14 — servizio lingua, servizio stato (UP/DOWN/UNREACHABLE), pagina stato, shell |
| Frontend build produzione | ✅ 71.7 kB trasferiti iniziali |
| Agent (`go vet`, `go test`) | ✅ 6 test CLI; cross-compile 7 target; binario Windows eseguito |
| Stack Compose end-to-end | ✅ tutti i servizi healthy; HTTP→HTTPS 301; `/healthz` UP; `/actuator/env` 404; API 404 `application/problem+json` con HSTS/CSP; SPA e i18n serviti; TLS 1.1 rifiutato; nessuno script inline |
| Ruoli DB nello stack reale | ✅ `shsc_app` e `shsc_migrator` senza superuser/BYPASSRLS; V001 applicata |
| Backup | ✅ dump valido (header PGDMP) creato |
| `nginx -t` / `docker compose config` | ✅ |
| gitleaks | ✅ nessun segreto nei file tracciabili (segnalato solo il `.env` locale, escluso da git) |

**Non verificato**: la pipeline CI non è ancora stata eseguita su GitHub (nessun remote); rendering visivo nel browser non verificato perché il certificato self-signed non è attendibile nel browser integrato (verificato via HTTPS con curl).

### Problemi riscontrati
1. Anche `C:\Users\mohamed` è un repository git (`progetto-d-esame`): il repository del progetto è indipendente, ma evitare `git add` dalla home.
2. Il redirect HTTP→HTTPS usa la porta 443: in dev con porte personalizzate (8080/8443) aprire direttamente `https://localhost:8443`.
3. Il primo avvio dei test backend è lento (~2–4 min) per il download di dipendenze e immagini; poi la cache Maven è nel volume `shsc-maven-cache`.
4. Toolchain locale ancora non aggiornata (Java 21, Node 24, Go): non blocca grazie ai container, utile per l'IDE.

## Decisioni aperte (richiedono risposta)
1. Remote git del progetto (GitHub privato?) — necessario per eseguire la CI.
2. ~~ADR-005 Autenticazione~~ → risolta: in-house (Milestone 3).
3. ADR-012 Probe accesso anonimo MQTT: disabilitate (proposta) o opt-in?
4. Hosting di produzione (VPS UE proposta) e dominio.
5. Costi futuri: firma codice agent, Apple Developer, provider AI.
