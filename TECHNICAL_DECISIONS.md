# Technical Decisions (ADR)

Formato: contesto → decisione → alternative → conseguenze. Stato: **Proposta** finché non approvata, poi **Accettata**.

| ID | Decisione | Stato |
|---|---|---|
| ADR-001 | Repository git dedicato | Accettata (eseguita in M2) |
| ADR-002 | Monolite modulare Spring Boot | Accettata |
| ADR-003 | Versioni dello stack | Accettata (versioni fissate in M2) |
| ADR-004 | Multi-tenancy: schema condiviso + `tenant_id` + RLS | Accettata |
| ADR-005 | Autenticazione in-house con Spring Security | Accettata (implementata in M3) |
| ADR-006 | Agent: connessione solo in uscita, long-polling | Accettata |
| ADR-007 | Identità agent: Ed25519 + private_key_jwt (mTLS rimandato) | Accettata |
| ADR-008 | Update agent: manifest firmato Ed25519, TUF in futuro | Accettata |
| ADR-009 | Agent = sensore, backend = analisi | Accettata |
| ADR-010 | Nessun Npcap / niente raw SYN scan | Accettata |
| ADR-011 | Scansioni solo manuali, vincolo DB `trigger='MANUAL'` | Accettata |
| ADR-012 | Probe "accesso anonimo" (MQTT) disabilitate | Proposta — da confermare |
| ADR-013 | Librerie open source scelte | Accettata |
| ADR-014 | Due ruoli DB: migrator (DDL) e app (solo DML, no BYPASSRLS) | Accettata (M2) |
| ADR-015 | Build e test containerizzati, CI GitHub Actions | Accettata (M2) |
| ADR-016 | Un solo container Nginx: TLS, reverse proxy e frontend statico | Accettata (M2) |
| ADR-017 | Persistenza JDBC esplicita al posto di JPA | Accettata (M3) |
| ADR-018 | Lookup pre-autenticazione con funzioni `SECURITY DEFINER` sotto RLS | Accettata (M3) |
| ADR-019 | Refresh token opachi a rotazione, sessioni per dispositivo | Accettata (M3) |
| ADR-020 | CSRF double-submit solo sugli endpoint a cookie | Accettata (M3) |
| ADR-021 | Token agent opachi (non JWT) e asserzioni Ed25519 | Accettata (M3) |
| ADR-022 | Throttling in PostgreSQL al posto di Bucket4j | Accettata (M3) |
| ADR-023 | Lista locale di password comuni (HIBP solo previa approvazione) | Accettata (M3) |
| ADR-024 | Utenti disattivati, mai cancellati | Proposta (implementata in M4) |
| ADR-025 | Inviti con link monouso; password scelta dall'invitato | Proposta (implementata in M4) |
| ADR-026 | Ambito di ruolo CUSTOMER | Proposta (implementata in M4) |
| ADR-027 | Limiti del piano in tabella, verificati sotto lock | Proposta (implementata in M4) |
| ADR-028 | Reti dichiarate: solo intervalli privati, doppia barriera | Proposta (implementata in M4) |
| ADR-029 | Autorizzazione di rete con attestazione versionata | Proposta (implementata in M4) |
| ADR-030 | PUT a sostituzione completa, PATCH solo per gli utenti | Proposta (implementata in M4) |

---

### ADR-001 — Repository git dedicato
**Contesto**: il progetto era dentro `Desktop\lavoro`, repository git con remote `webmedica/terapANGULAR` e file sensibili non tracciati. **Decisione (eseguita 16/11/2026)**: progetto spostato su richiesta in `C:\Users\mohamed\Desktop\smart-home-security-check`, `git init -b main`. Anche `C:\Users\mohamed` è un repository git (remote `progetto-d-esame`): i comandi git eseguiti nella cartella del progetto usano il repository del progetto; **non** eseguire `git add` dalla home. Remote del progetto: da definire. **Conseguenze**: nessun rischio di commit nel repo aziendale.

### ADR-002 — Monolite modulare
**Decisione**: un solo deployable Spring Boot con moduli per dominio e confini verificati (ArchUnit/Spring Modulith). **Alternative**: microservizi (scartati: costi operativi, team piccolo). **Conseguenze**: deploy semplice ed economico; estrazione futura possibile (es. `vulnintel`).

### ADR-003 — Versioni target
Versioni fissate in Milestone 2 (verificate su Maven Central / npm / go.dev il 16/11/2026):

| Componente | Versione | Dove è fissata |
|---|---|---|
| Java | 21 LTS (Temurin) | `pom.xml`, immagini `maven:3.9-eclipse-temurin-21`, `eclipse-temurin:21-jre-alpine` |
| Spring Boot | **4.1.2** | `pom.xml` (parent) |
| springdoc-openapi | 3.2.0 | `pom.xml` |
| Maven | 3.10.0 via Maven Wrapper | `.mvn/wrapper` |
| PostgreSQL | 18 (`postgres:18-alpine`) | `docker-compose.yml`, test |
| Angular / CLI | 22.2.x | `package.json` + `package-lock.json` |
| Node.js | 24 LTS | Dockerfile Nginx, CI (Angular 22 richiede ≥ 22.22 o ≥ 24.15) |
| TypeScript / Vitest | 6.0 / 5.x | `package.json` |
| Transloco | 8.4.0 | `package.json` |
| Go | 1.27 | `go.mod`, `golang:1.27-alpine`, CI |
| Nginx | 1.28 (`nginx:1.28-alpine`) | Dockerfile |
| Mailpit (solo dev) | v1.33.1 | `docker-compose.yml` |
| Flutter | stable — fissata in M14 | — |

Scelta Spring Boot 4.x invece di 3.5.x: la linea 3.5 è a fine supporto OSS e tutte le dipendenze necessarie in M2 sono compatibili con la 4.1.

### ADR-004 — Multi-tenancy
**Decisione**: database e schema condivisi, `tenant_id` su ogni tabella tenant-scoped, Row-Level Security PostgreSQL con `SET LOCAL app.tenant_id`, ruolo DB applicativo senza `BYPASSRLS`. **Alternative**: schema per tenant / DB per tenant (scartati: migrazioni e pool non scalano su molti tenant piccoli). **Conseguenze**: doppia barriera (app + DB), test di isolamento obbligatori.

### ADR-005 — Autenticazione
**Decisione** (confermata per la Milestone 3, niente Auth0/Firebase): in-house con Spring Security 7.
- Access token JWT **ES256** di 15 min (Nimbus, chiave P-256 da `SHSC_JWT_PRIVATE_KEY`, `kid` = thumbprint).
- Refresh opaco a rotazione in cookie HttpOnly; Argon2id.
- A ogni richiesta il principal viene ricaricato dal DB (sessione, utente, ruoli): revoche e cambi di ruolo hanno effetto immediato. Il costo è una query in più per richiesta, accettabile per l'MVP e cacheabile in futuro.

**Alternativa scartata**: Keycloak, con un servizio in più (~1 GB RAM) e la multi-tenancy da modellare nei realm.

**Estensioni previste**: MFA TOTP con un passo `mfaRequired` nel login; OIDC con `oauth2Login` che apre una sessione con `SessionService.open`. `password_hash` è nullable per gli account solo-OIDC. Dettagli in [docs/12-AUTHENTICATION.md](docs/12-AUTHENTICATION.md).

### ADR-006 — Canale agent
**Decisione**: HTTPS in uscita, long-polling per i job, POST per progress/risultati. **Alternative**: WebSocket (più complesso dietro proxy, da valutare per monitoraggio continuo), MQTT broker (servizio in più). **Conseguenze**: nessuna porta aperta in casa, funziona dietro NAT/CGNAT.

### ADR-007 — Identità agent
**Decisione**: Ed25519 generata localmente, enrollment con token monouso, asserzione JWT firmata → access token 10 min; job firmati dal backend. **Alternativa**: mTLS con CA privata (rimandata a hardening).

### ADR-008 — Aggiornamenti agent
**Decisione**: manifest firmato Ed25519 con chiave di release offline, anti-rollback, rollback automatico. **Futuro**: TUF (`go-tuf`) per rotazione chiavi e protezione freeze.

### ADR-009 — Divisione responsabilità
Agent raccoglie osservazioni/evidenze; backend classifica, analizza, calcola rischio (regole centralizzate, ri-analisi possibile).

### ADR-010 — Niente Npcap, TCP connect scan
Npcap richiede licenza OEM a pagamento per la redistribuzione commerciale. Su Windows si usano API iphlpapi. TCP connect scan al posto di SYN scan.

### ADR-011 — Solo scansioni manuali nell'MVP
`ScanTrigger` con unico valore attivo `MANUAL`, vincolo `CHECK` nel DB, nessuno scheduler. I job periodici ammessi sono solo di manutenzione/sync dati pubblici.

### ADR-012 — Probe di accesso anonimo
Un `CONNECT` MQTT senza credenziali rivelerebbe broker aperti (rischio reale e comune) ma costituisce un tentativo di accesso. **Proposta**: disabilitato; eventualmente opt-in esplicito per rete, in futuro. **Da decidere.**

### ADR-013 — Librerie (tutte open source, nessun costo)
| Area | Libreria | Licenza | Motivo |
|---|---|---|---|
| Backend | Spring Boot (webmvc, jdbc, security, oauth2-resource-server, mail, validation, actuator), Flyway, springdoc-openapi, Testcontainers | Apache 2.0 | standard di fatto (Data JPA e Bucket4j non usati: ADR-017, ADR-022) |
| Backend | Nimbus JOSE + JWT (incluso in Spring Security) | Apache 2.0 | firma e verifica JWT ES256 |
| Backend | BouncyCastle `bcprov-jdk18on` 1.86 | MIT | richiesto da `Argon2PasswordEncoder`; usato anche per derivare la chiave pubblica P-256. 1.87 scartata perché pubblicata da troppo poco tempo |
| Backend PDF | openhtmltopdf (fork mantenuto) + Thymeleaf | LGPL / Apache 2.0 | report HTML→PDF; alternativa Apache PDFBox |
| Frontend | Angular Material/CDK, Transloco, ngx-echarts/ECharts, Cytoscape.js, Playwright | MIT / Apache 2.0 | i18n runtime IT/EN, grafici, mappa rete |
| Agent | `golang.org/x/net`, `golang.org/x/sys`, `mdlayher/arp`, `miekg/dns`, `gosnmp/gosnmp`, `kardianos/service`, `modernc.org/sqlite`, `gopacket` (solo macOS/Linux opzionale) | BSD/MIT | pure Go dove possibile → cross-compile senza CGO |
| Mobile | Riverpod, dio, go_router, flutter_secure_storage, firebase_messaging | MIT/BSD/Apache | FCM gratuito |
| Servizi esterni | NVD API, CISA KEV, FIRST EPSS, IEEE OUI | gratuiti | dati pubblici ufficiali |
| A pagamento (da approvare) | Stripe (commissioni per transazione), certificati firma codice, Apple Developer, provider AI, hosting | — | non introdotti finché non approvati |

### ADR-014 — Ruoli database separati
**Contesto**: la RLS (ADR-004) è inefficace se l'applicazione si connette come owner delle tabelle o con `BYPASSRLS`. **Decisione**: lo script `infrastructure/docker/postgres/init/01-roles.sh` crea `migrator` (owner dello schema `shsc`, esegue Flyway) e `app` (runtime, solo `SELECT/INSERT/UPDATE/DELETE` tramite `ALTER DEFAULT PRIVILEGES`, `NOSUPERUSER NOBYPASSRLS`). Il superuser del container serve solo all'inizializzazione e ai backup. La funzione `shsc.current_tenant_id()` (V001) legge `app.tenant_id` impostato per transazione. **Verifica**: `DatabaseBaselineTest` usa lo stesso script di init. **Conseguenze**: le estensioni ammesse sono solo quelle *trusted* (citext, pg_trgm); estensioni non trusted richiedono l'intervento del superuser.

### ADR-015 — Toolchain containerizzata e CI
**Contesto**: la macchina di sviluppo non ha Go, ha Node 18 e `JAVA_HOME` rotto. **Decisione**: build e test girano in container ufficiali (`infrastructure/scripts/test-backend.sh`, `build-agent.sh`, `node:24-alpine` per Angular); i test backend usano Testcontainers tramite il socket Docker dell'host. CI su GitHub Actions (`.github/workflows/ci.yml`): backend, frontend (+ `npm audit`), agent (`go vet`, `-race`, cross-compile, `govulncheck`), validazione Compose/Nginx, gitleaks. **Costo**: gratuito per repository pubblici; per repository privati GitHub include minuti gratuiti mensili.

### ADR-016 — Nginx unico
**Decisione**: un'immagine Nginx costruisce il frontend Angular (multi-stage) e fa da terminatore TLS e reverse proxy verso il backend. Header di sicurezza (HSTS, CSP senza script inline, `frame-ancestors 'none'`, nosniff), rate limit per IP (`/api/` 20 r/s, `/api/v1/auth/` 10 r/min), actuator bloccato tranne `/healthz`. Certificato: self-signed generato all'avvio solo con `SHSC_TLS_SELF_SIGNED=true` (dev); in produzione certificati reali montati nel volume `tls-certs`. Rete `data` interna: PostgreSQL non è raggiungibile dall'esterno. Nota: nel build Angular è disattivato `inlineCritical` perché inserisce un handler `onload` inline incompatibile con la CSP.

### ADR-017 — Persistenza JDBC esplicita al posto di JPA
**Contesto**: con la RLS, `app.tenant_id` va impostato su **ogni** connessione all'inizio di ogni transazione. Le query pre-autenticazione devono poi passare da funzioni dedicate. **Decisione**: `spring-boot-starter-jdbc` + `JdbcClient` con SQL esplicito. `TenantAwareTransactionManager` (estende `JdbcTransactionManager`) esegue `set_config('app.tenant_id', ?, true)` all'apertura della transazione, leggendo il valore dal `TenantContext`. Ogni accesso al DB avviene dentro una transazione. **Alternative**: Data JPA con un interceptor Hibernate (scartata: lazy loading e flush fuori transazione rendono difficile garantire che il contesto tenant sia sempre impostato). **Conseguenze**: più SQL scritto a mano, ma query visibili e revisionabili; nessuna entità gestita.

### ADR-018 — Lookup pre-autenticazione con funzioni `SECURITY DEFINER`
**Contesto**: al login o al refresh il tenant non è ancora noto, ma la RLS nasconde tutte le righe. **Decisione**: funzioni `SECURITY DEFINER` di proprietà del migrator, con `search_path` fissato, che restituiscono **solo** il `tenant_id`:
- `auth_lookup_user(email)`;
- `lookup_tenant_by_secret(kind, sha256)`;
- `agent_lookup_tenant(agentId)`.

Dopo il lookup la lettura vera avviene sotto RLS, nel tenant trovato. `EXECUTE` è revocato a `PUBLIC` e concesso solo al ruolo app (verificato da `DatabaseBaselineTest`). **Alternativa**: ruolo con `BYPASSRLS` per l'autenticazione (scartata: un bug esporrebbe tutti i tenant).

### ADR-019 — Refresh token opachi a rotazione, sessioni per dispositivo
**Decisione**:
- Il refresh è un valore casuale di 256 bit (`shsc_rt_…`). Nel DB c'è solo lo SHA-256, legato a una riga `user_sessions` per dispositivo.
- Ruota a ogni uso. Presentare un token già ruotato o revocato revoca l'intera sessione e lo registra in audit.
- Cookie `HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth`.
- Durata configurabile tra 7 e 30 giorni (default 14), con un tetto assoluto di sessione di 30 giorni.
- Nel frontend il refresh è serializzato tra schede (Web Locks), così due schede non presentano lo stesso token, che verrebbe scambiato per un furto.

**Alternativa**: refresh JWT (scartata: non revocabile senza lo stesso stato in DB).

### ADR-020 — CSRF double-submit solo sugli endpoint a cookie
**Decisione**: `CookieCsrfTokenRepository` (cookie `XSRF-TOKEN` leggibile, `Secure`, `SameSite=Strict`) + header `X-XSRF-TOKEN`. È richiesto solo sui metodi mutanti di `/api/v1/auth/**`, l'unico posto in cui il browser invia credenziali automaticamente (il cookie refresh). Le altre API usano solo `Authorization: Bearer`, che il browser non allega da solo.

La rotazione del token CSRF all'autenticazione (`CsrfAuthenticationStrategy`) è **disattivata** (`NullAuthenticatedSessionStrategy`). Altrimenti ogni richiesta Bearer cancellerebbe il cookie e il refresh successivo fallirebbe con 403: è il difetto trovato nella verifica end-to-end, ora coperto da un test. Non esiste una sessione server da fissare.

### ADR-021 — Token agent opachi e asserzioni Ed25519
**Decisione**:
- L'agent si autentica con un'asserzione JWS EdDSA a vita breve: ≤ 60 s, `jti` monouso, audience dedicata.
- In cambio riceve un token **opaco** `shsc_at_` di 10 min (solo hash in DB). A ogni richiesta vengono verificati token, credenziale e stato dell'agent.

Così una revoca o una rotazione hanno effetto **subito**, senza liste di revoca per JWT. Le API agent hanno una filter chain separata: un JWT utente non è mai accettato, e viceversa. La rotazione richiede una prova firmata con la nuova chiave. **Alternativa**: mTLS (rimandata: richiede una CA privata e gestione dei certificati sugli agent).

### ADR-022 — Throttling in PostgreSQL al posto di Bucket4j
**Decisione**: la tabella `auth_throttle` contiene contatori con finestra e blocco progressivo:
- per account, con email hashata (dopo 5 errori, blocco da 1 min fino a 1 h);
- per IP (30 errori, poi 15 min).

Gli endpoint che inviano email hanno quote separate. Lo stato è condiviso tra più istanze senza Redis. Nginx aggiunge un limite per IP. **Alternativa**: Bucket4j con un backend JDBC (una dipendenza in più per lo stesso risultato). **Conseguenza**: una scrittura in DB per ogni tentativo fallito; i record scaduti sono rimossi dal job orario `purge_expired_auth_data`.

### ADR-023 — Lista locale di password comuni
**Decisione**: un file di password comuni è incluso nel backend (`security/common-passwords.txt`), insieme a controlli di lunghezza (12–128), ripetizioni e sequenze, e dati personali. **Futuro**: Have I Been Pwned Pwned Passwords (k-anonymity, gratuito, nessun dato personale inviato) è un servizio esterno, quindi **da approvare** prima dell'introduzione.

### ADR-024 — Utenti disattivati, mai cancellati
**Decisione**: nessun endpoint cancella fisicamente un utente.

La disattivazione (`status = DISABLED`):
- revoca subito tutte le sessioni e i token monouso;
- conserva i ruoli.

La riattivazione riporta l'utente ad `ACTIVE`, oppure a `PENDING_VERIFICATION` se l'email non è mai stata verificata. È soggetta al limite del piano. Gli utenti disattivati non contano nel limite utenti, né nel conteggio degli amministratori per la regola `LAST_ADMIN`.

**Motivazione**: l'audit e le autorizzazioni di rete fanno riferimento all'utente. La cancellazione su richiesta dell'interessato (GDPR) sarà un processo di anonimizzazione dedicato (milestone admin/GDPR).

### ADR-025 — Inviti con link monouso; l'invitato sceglie la password
**Decisione**: l'amministratore non sceglie né vede mai la password.
- L'utente è creato senza password.
- Un token `INVITATION` (hash in DB, TTL 7 giorni, nel frammento URL) permette di impostarla una sola volta. Al rinvio i token precedenti vengono invalidati.

**Compromesso**: se l'email ha già un account (in qualunque tenant) l'invito risponde `409 EMAIL_ALREADY_REGISTERED`. Questo rivela l'esistenza dell'account, ma solo a un amministratore autenticato, con quota email per IP e audit. L'alternativa (rispondere "invito inviato" senza crearlo) confonderebbe l'amministratore. Il multi-tenant per lo stesso utente è predisposto (`tenant_memberships`) ma fuori MVP.

### ADR-026 — Ambito di ruolo CUSTOMER
**Decisione**: nuovo `scope_type = CUSTOMER`. Un ruolo su un cliente vale per il cliente e per tutte le sue abitazioni, comprese quelle create dopo. Così un MSP non deve riassegnare i ruoli a ogni nuova casa.

Gli ambiti HOME e CUSTOMER non sono *tenant-wide*: non danno accesso a utenti, organizzazione o gestione clienti, e non vedono i dati di uso del tenant. Creare abitazioni dentro il proprio cliente è consentito. Spostarle tra clienti richiede i diritti su entrambi.

### ADR-027 — Limiti del piano in tabella, verificati sotto lock
**Decisione**:
- I limiti sono colonne esplicite della tabella `plans`, non jsonb, per avere vincoli e query semplici. La tabella non è scrivibile dal ruolo applicativo.
- `tenants.plan_code` vale `FREE` di default.
- La verifica blocca la riga del tenant (`SELECT … FOR UPDATE`) nella stessa transazione della creazione: niente superamenti per richieste concorrenti.

I limiti valgono solo per nuove creazioni e riattivazioni. I tenant di sviluppo creati prima della Milestone 4 possono già superarli: i dati esistenti non vengono toccati. Abbonamenti e pagamenti (Stripe) restano fuori, in attesa di approvazione. Il limite agent per abitazione arriva con la Milestone 5.

### ADR-028 — Reti dichiarate: solo intervalli privati, doppia barriera
**Decisione**: nella Milestone 4 le reti sono dichiarate dall'utente (`source = MANUAL`). Quelle proposte dall'agent arriveranno con l'agent di discovery.

Accettiamo solo intervalli privati o locali di dimensione limitata (≥ /22 IPv4, ≥ /64 IPv6) senza sovrapposizioni nella stessa abitazione. Il controllo è doppio:
- nel codice: parser senza DNS, senza zeri iniziali, senza zone id;
- nel database: `CHECK` con l'operatore `<<=` sul tipo `cidr`.

L'intervallo è immutabile: per cambiarlo si elimina e si ricrea, così un'autorizzazione non "segue" mai un intervallo diverso.

**Motivazione**: è il primo vincolo per non scansionare mai reti di terzi o Internet (`docs/10-RISKS-LIMITATIONS.md`). Anche l'agent rifiuterà target fuori dalle sue subnet direttamente connesse.

### ADR-029 — Autorizzazione di rete con attestazione versionata
**Decisione**: autorizzare una rete richiede `attestation: true` più la versione del testo che l'utente ha visto (`attestationVersion`, oggi "1", testo i18n `networks.attestation.v1`). La casella non è mai preselezionata. Una versione diversa è rifiutata (`ATTESTATION_OUTDATED`), quindi un testo cambiato va riconfermato.

Le autorizzazioni non vengono mai sovrascritte:
- nuovo record per ogni autorizzazione, con revoca e storico;
- indice unico parziale per una sola autorizzazione attiva;
- audit con utente, data, intervallo e versione.

Autorizzare non avvia nulla: nell'MVP non esistono scansioni automatiche.

### ADR-030 — PUT a sostituzione completa, PATCH solo per gli utenti
**Decisione**: organizzazione, clienti, abitazioni e reti si aggiornano con `PUT`, inviando tutti i campi modificabili: i campi facoltativi omessi vengono svuotati. Così il client non ha ambiguità tra "non inviato" e "da cancellare". Per gli utenti `PATCH` resta parziale, perché nome e stato sono operazioni indipendenti con regole diverse (disattivazione = revoca sessioni).
