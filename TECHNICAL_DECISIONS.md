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

### ADR-031 — Coda locale dell'agent in SQLite puro Go (`modernc.org/sqlite`)
**Decisione**: la coda offline dell'agent è un database SQLite (`queue.db`, WAL, `synchronous=FULL`) gestito con `modernc.org/sqlite` v1.62 (licenza BSD-3, open source, gratuito), una traduzione in Go puro di SQLite. Ogni elemento ha una chiave scelta dal produttore (idempotenza), viene cancellato solo dopo la conferma del backend e la coda ha un tetto di 200 MB oltre il quale si eliminano i più vecchi con evento `QUEUE_OVERFLOW`.

**Motivazione**: è la scelta già prevista dal protocollo (doc 03 §8). Il driver puro Go evita cgo e un compilatore C, quindi la cross-compilazione dei 7 binari (Windows, Linux, macOS, ARM) resta un semplice `go build`. Alternativa scartata: `mattn/go-sqlite3` (richiede cgo).

### ADR-032 — Servizi di sistema con `golang.org/x/sys`, senza `kardianos/service`
**Decisione**: installazione e gestione del servizio sono scritte direttamente: Windows con `golang.org/x/sys/windows/svc` e `svc/mgr` (BSD-3, mantenuto dal team Go), Linux con un file di unità systemd generato, macOS con un plist launchd generato.

**Motivazione**: serve un controllo fine che la libreria generica non offre in modo uniforme: account `LocalService`, avvio ritardato e azioni di ripristino su Windows; `CAP_NET_RAW` come unico privilegio e sandboxing su systemd; nessun riavvio dopo una revoca (codici di uscita 3 e 4 esclusi, `KeepAlive` launchd legato all'esistenza di `agent.json`). `x/sys` serve comunque per DPAPI, ACL e iphlpapi. Una dipendenza in meno.

### ADR-033 — Heartbeat ogni 25 s, intervallo deciso dal server
**Decisione**: l'agent invia l'heartbeat ogni 25 s (`shsc.agent.heartbeat-interval`, comunicato nella risposta), anticipando a caso fino al 10 %, mai ritardando. La connettività è calcolata alla lettura: ONLINE < 3 min, STALE < 15 min, poi OFFLINE.

**Motivazione**: il criterio della milestone chiede che un agent revocato smetta di operare entro 30 s. Il backend ricontrolla la credenziale a ogni richiesta, quindi l'intervallo di heartbeat è il ritardo massimo: 25 s lascia margine per la latenza. Il costo è basso (una richiesta piccola ogni 25 s per agent) e l'intervallo si può aumentare dal server senza aggiornare gli agent.

### ADR-034 — Chiave privata dell'agent su Windows: DPAPI machine scope e ACL esplicita
**Decisione**: su Windows la chiave Ed25519 è cifrata con DPAPI in ambito macchina con entropia applicativa e la cartella di stato riceve una ACL protetta (SYSTEM, Administrators, LocalService, utente che ha fatto l'enrollment). Su Linux e macOS resta un file `0600` in una cartella `0700` di root/`shsc` (il Keychain di sistema di macOS è rimandato).

**Motivazione**: su Windows i permessi POSIX non hanno effetto e `%ProgramData%` eredita permessi di lettura per gli utenti. L'ambito macchina permette al servizio `LocalService` di leggere la chiave creata da un amministratore durante l'enrollment; un file copiato su un'altra macchina è inutilizzabile. Il Keychain di macOS richiederebbe cgo o un processo esterno e non migliora la protezione rispetto a root + `0600` per un daemon.

### ADR-035 — Limite di agent per abitazione
**Decisione**: `plans.max_agents_per_home` (FREE: 2). Il limite conta solo agent `ACTIVE` ed è verificato due volte: alla creazione del token (per avvisare subito) e all'enrollment, nella stessa transazione e sotto lo stesso lock del tenant degli altri limiti (ADR-027). Se l'enrollment è rifiutato il token resta utilizzabile.

**Motivazione**: completa i limiti del piano FREE rimandati dalla M4. Due agent coprono il caso tipico (un PC e un mini-PC o Raspberry); revocare un agent libera il posto.

### ADR-036 — Eventi dell'agent: idempotenti, ultimi 500 per agent
**Decisione**: gli eventi hanno un `id` scelto dall'agent e un vincolo `UNIQUE(agent_id, event_id)`, così un reinvio dopo una conferma persa è un duplicato innocuo. Il backend conserva gli ultimi 500 eventi per agent (pulizia a ogni consegna) e limita `detail` a 4 KB; date oltre 5 minuti nel futuro sono sostituite con l'ora del server. Nessun partizionamento della tabella nell'MVP.

**Motivazione**: gli eventi servono alla diagnosi recente, non all'audit (che resta in `audit_logs`). Un tetto per agent limita lo spazio occupato da un agent difettoso o malevolo senza un job di pulizia separato.

### ADR-037 — Job di scansione firmati Ed25519 con chiave pubblica fissata nell'agent
**Decisione**: il backend firma ogni job con una chiave Ed25519 dedicata (`SHSC_JOB_SIGNING_KEY`, diversa da quella dei JWT). L'agent riceve la chiave pubblica all'enrollment, la salva in `agent.json` e rifiuta ogni job non firmato con quella chiave. Gli agent registrati prima della M6 la ottengono una sola volta dalla sessione, su TLS verificato.

**Motivazione**: il job decide quali reti l'agent sonda. Con la firma, nemmeno chi controlla un proxy o il canale TLS può far sondare all'agent reti diverse da quelle autorizzate. Ed25519 è nella libreria standard di Java e di Go: nessuna dipendenza nuova.

### ADR-038 — Long polling sui thread virtuali invece di WebSocket
**Decisione**: l'agent ritira i job con `GET /agent/jobs/next?wait≤25`. La richiesta resta aperta su un thread virtuale, viene svegliata dopo il commit della richiesta di scansione e il backend ricontrolla il database ogni 5 s.

**Motivazione**: funziona dietro proxy e firewall domestici come una normale richiesta HTTPS, senza nuove dipendenze né stato di connessione da gestire in nginx. Il ricontrollo periodico copre più istanze del backend e notifiche perse. Una connessione aperta per agent costa poco sui thread virtuali.

### ADR-039 — Lease rinnovato dal progress e reaper nel database
**Decisione**: una scansione `RUNNING` ha un lease di 2 min rinnovato da ogni progress. Un reaper ogni 30 s fa fallire le scansioni con coda scaduta (10 min), lease scaduto o durata oltre 15 min. Usa una funzione `SECURITY DEFINER` perché opera su tutti i tenant nonostante la RLS. I risultati arrivati dopo un `AGENT_LOST` sono accettati per 24 h (`LATE_UPLOAD`).

**Motivazione**: nessuna scansione resta "in corso" per sempre se l'agent si spegne. La funzione espone solo gli identificativi da chiudere, senza dare al ruolo applicativo il bypass della RLS. La finestra di 24 h evita di perdere il lavoro di un agent rimasto senza connessione.

### ADR-040 — Risultati a lotti idempotenti e verifica dell'ambito lato server
**Decisione**: i risultati arrivano in lotti numerati (massimo 500), idempotenti su `(scan_id, batch_seq)`; `complete` richiede tutti i lotti. Ogni IP è confrontato con gli obiettivi della scansione: quelli fuori ambito sono scartati, contati e registrati in audit.

**Motivazione**: la coda locale dell'agent può reinviare. Il backend non si fida dell'agent per l'ambito: la regola "nessun dato da reti non autorizzate" vale anche per un agent difettoso o compromesso.

### ADR-041 — Discovery M6 solo ARP, senza dipendenze di cattura
**Decisione**: Windows usa `SendARP` (IP Helper API); Linux usa socket `AF_PACKET` con `CAP_NET_RAW` e, senza la capability, legge `/proc/net/arp`. macOS è rimandato. Nessun Npcap, libpcap o gopacket.

**Motivazione**: è la discovery minima prevista dalla roadmap. Funziona senza installare driver e senza privilegi su Windows, ed è limitata alle sottoreti collegate direttamente. ICMP, mDNS e SSDP arrivano con la milestone della discovery completa.

### ADR-042 — `golang.org/x/net` per ICMP, IPv4/IPv6 e messaggi DNS
**Decisione**: i pacchetti `icmp`, `ipv4`, `ipv6` e `dns/dnsmessage` di `golang.org/x/net` (v0.62.0, BSD-3-Clause, gratuito, mantenuto dal Go team) per echo ICMP/ICMPv6, opzioni multicast e mDNS/DNS-SD. Su Windows l'ICMP usa l'IP Helper API (`IcmpSendEcho2Ex`) tramite `golang.org/x/sys`, già presente.

**Alternative**: `miekg/dns` (BSD-3, più ampio del necessario), `hashicorp/mdns` (MIT, non permette di scegliere interfaccia e limiti), `pro-bing` (MIT, solo ICMP). Scartate per superficie e controllo dell'ambito.

### ADR-043 — `gosnmp` per l'integrazione SNMP del router
**Decisione**: `github.com/gosnmp/gosnmp` v1.47.0 (BSD-2-Clause, gratuito) per SNMP v2c/v3 in sola lettura (Get, BulkWalk). Usato solo con credenziali configurate dal proprietario; community `public`/`private` rifiutate.

**Alternative**: implementazione BER propria (rischio di errori, USM v3 complesso), net-snmp via cgo (dipendenza nativa, cross-compilazione). Scartate.

### ADR-044 — URL annunciati dai dispositivi: solo l'IP del dispositivo stesso
**Decisione**: un URL annunciato (SSDP `LOCATION`, UPnP `controlURL`/`URLBase`, TR-064) è seguito solo se è `http`, senza user-info e con host uguale all'IP letterale del dispositivo che lo ha annunciato, nell'ambito. Client senza proxy né redirect, dialer vincolato a quell'IP, 3 s, 256 KB, `encoding/xml`.

**Motivazione**: un dispositivo ostile potrebbe usare l'agent per raggiungere altri host (SSRF), anche fuori dalle reti autorizzate. Il vincolo nel dialer protegge anche da errori futuri nel controllo degli URL.

### ADR-045 — Credenziali del router solo sull'agent
**Decisione**: le credenziali TR-064/SNMP sono inserite dal proprietario sull'agent (`shsc-agent router`, segreti da stdin) e salvate protette come la chiave dell'agent; il backend conosce solo i nomi delle integrazioni. Un rifiuto delle credenziali interrompe l'integrazione senza retry.

**Motivazione**: il SaaS non deve custodire credenziali della rete domestica; il dato resta dove viene usato. Nessun tentativo ripetuto evita blocchi dell'account del router e qualsiasi somiglianza con il password guessing.

### ADR-046 — Ruleset di classificazione in JSON, validato all'avvio
**Decisione**: le regole di fingerprinting stanno in `fingerprint/rules.json` (versione nel file, salvata con ogni risultato), lette con Jackson già presente e validate all'avvio: id univoci, nessuna regola che conclude `UNKNOWN_DEVICE`, peso `WEAK` sempre sotto la soglia. Un ruleset non valido blocca l'avvio.

**Motivazione**: docs/07 prevedeva YAML, che avrebbe richiesto un parser in più (nessuna nuova dipendenza è stata aggiunta). JSON è già supportato, versionabile in git e testabile; la validazione impedisce che un errore nelle regole porti a classificazioni sbagliate in silenzio.

### ADR-047 — Classificazione: soglia più indizi indipendenti, mai un solo indizio debole
**Decisione**: pesi STRONG 60 / MODERATE 30 / WEAK 10, soglia 50; una categoria è scelta solo con un indizio STRONG o due MODERATE da fonti diverse. Conferma indipendente → alta; un'altra categoria qualificata abbassa di un livello; parità → `UNKNOWN_DEVICE`. La categoria manuale non è mai sovrascritta; una rilevazione diversa e affidabile è solo un suggerimento.

**Motivazione**: un falso "è una telecamera" è peggio di "non identificato": il rischio (M10) dipenderà dalla categoria. Il produttore OUI è quello della scheda di rete, quindi resta un indizio debole.

### ADR-048 — Registro OUI IEEE nel backend, sincronizzazione solo manuale
**Decisione**: i CSV pubblici IEEE (MA-L, MA-M, MA-S) sono scaricati solo su richiesta di un amministratore di piattaforma, con HTTPS, limiti di dimensione e tempo, e sostituiti in un'unica transazione solo se tutti i file sono stati letti. La ricerca avviene nel backend; lo snapshot per l'agent previsto in docs/07 non è necessario. Sorgenti configurabili (`SHSC_OUI_SOURCES`).

**Motivazione**: nessun servizio a pagamento né account; nessuna attività automatica verso l'esterno; un download fallito non lascia il registro a metà. L'agent non ha bisogno del registro perché la classificazione è fatta lato server.

### ADR-049 — Porte: salvate solo quelle aperte, le altre come contatori per host
**Decisione**: `open_ports` contiene solo le porte `OPEN`, una riga per scansione; chiuse, filtrate, `OPEN_FILTERED` e `UNKNOWN` sono contate per host nell'osservazione `PORTSCAN` (con profilo e versione della lista). docs/08 prevedeva di salvare singolarmente anche filtrate e sconosciute; il vincolo unico è `(scan, ip, protocollo, porta)` invece di `(scan, device, …)` perché il dispositivo è noto solo alla chiusura della scansione.

**Motivazione**: STANDARD × 1024 host produrrebbe centinaia di migliaia di righe senza valore per l'utente né per il rischio; i contatori bastano per la copertura e per spiegare "senza risposta". Il collegamento al dispositivo avviene nel fingerprinting, nella stessa transazione della chiusura.

### ADR-050 — Liste porte nell'agent, versionate; UDP solo con probe sicura
**Decisione**: liste `QUICK`/`STANDARD` in `portlists.json` incorporato nell'agent (`go:embed`), versionato e validato all'avvio; il job firmato indica solo il profilo e i limiti. Una porta UDP è ammessa nella lista solo se esiste una probe di protocollo sicura; altrimenti la lista è rifiutata e la porta non viene mai contattata.

**Motivazione**: l'agent non deve poter ricevere dal server liste arbitrarie (difesa in profondità contro un backend compromesso); un file dati evita porte nel codice come richiesto da docs/08. Nessuna nuova dipendenza.

### ADR-051 — Profili DEEP e CUSTOM rimandati alla M17
**Decisione**: in M9 sono disponibili solo `QUICK` e `STANDARD` (anche per il piano FREE); `DEEP` e `CUSTOM` restano `400 PROFILE_NOT_AVAILABLE` e l'agent rifiuta job con profili sconosciuti.

**Motivazione**: sono legati ai piani a pagamento (M17) e `CUSTOM` richiede una validazione dei range che oggi non serve.

### ADR-052 — Timeout TCP fisso dal job, non adattivo
**Decisione**: timeout di connessione fisso (1,5 s dal job, ammessi 200–5000 ms) con un retry; il timeout adattivo sull'RTT ICMP di docs/08 non è implementato.

**Motivazione**: sulle LAN domestiche l'RTT è di pochi millisecondi e l'ICMP spesso è bloccato o non disponibile senza privilegi; un valore fisso e limitato è più prevedibile e verificabile. Da rivalutare con le misure della M18.

### ADR-053 — SMB: NEGOTIATE 2.0.2–3.0.2 e SMB1, senza 3.1.1
**Decisione**: l'agent invia solo `NEGOTIATE` SMB2 con i dialetti 2.0.2, 2.1, 3.0, 3.0.2 e un `NEGOTIATE` SMB1 ("NT LM 0.12") per sapere se SMB1 è accettato; mai `SESSION_SETUP`. Il dialetto 3.1.1 non è offerto.

**Motivazione**: 3.1.1 richiede i contesti di negoziazione (pre-auth integrity, cifratura) e non cambia ciò che interessa al rischio (SMB1 attivo, firma non obbligatoria); un dispositivo solo-3.1.1 risulta comunque `smb` probabile sulla porta 445.

### ADR-054 — Feed di vulnerabilità solo su richiesta, mirror limitato al dizionario CPE
**Decisione**: NVD, CISA KEV e FIRST EPSS sono sincronizzati solo quando un amministratore di piattaforma lo chiede (in background, una sincronizzazione alla volta); la sincronizzazione incrementale ogni 6 h di docs/09 non è implementata. Dalla NVD si scaricano solo le CVE dei prodotti del dizionario curato (`virtualMatchString`), con tutte le pagine lette prima di sostituire il mirror in un'unica transazione; EPSS solo per le CVE salvate. API key NVD opzionale e mai registrata nei log.

**Motivazione**: nessuna attività automatica verso l'esterno (come per l'OUI, ADR-048) e nessun servizio a pagamento; il mirror completo NVD (oltre 250 000 CVE) non serve, perché solo i prodotti del dizionario possono produrre un match. Un feed fallito non lascia dati a metà.

### ADR-055 — Matching CVE conservativo con dizionario curato e affidabilità della versione
**Decisione**: il prodotto dichiarato da un servizio diventa un CPE solo tramite un dizionario curato con nome intero per servizio (mai fuzzy, mai solo produttore); ogni voce indica l'affidabilità della versione (banner di protocollo `HIGH`, header HTTP/RTSP `MEDIUM`). `CONFIRMED_VULNERABILITY` solo con versione `HIGH`, servizio confermato, match esatto o nel range e nessuna condizione di piattaforma; configurazioni NVD negate ignorate, configurazioni AND → `POTENTIAL_RISK` con affidabilità bassa; versione ignota → un solo finding aggregato `PRODUCT_ONLY`. Il "CPE dictionary" NVD di docs/09 non è scaricato.

**Motivazione**: un falso "vulnerabilità confermata" mina la fiducia più di una mancata segnalazione; gli header HTTP sono facili da falsificare o generici. Il dizionario è piccolo, versionato e verificabile nei test; il CPE dictionary NVD porterebbe proprio i match approssimativi da evitare.

### ADR-056 — Catalogo regole M10: differenze da docs/09
**Decisione**: `snmp.enabled` è LOW/`POTENTIAL_RISK` (nessuna community viene mai provata, ADR-012: non si può dire che usi quella di default); `upnp.igd-enabled` e `dns.open-resolver` sono `POTENTIAL_RISK` (abilitano un abuso ma non sono una configurazione verificata come errata); `tls.legacy-protocol` considera TLS 1.0 e 1.1 (MEDIUM se non c'è niente di più recente); "nuovo dispositivo sconosciuto" diventa `device.unknown` (ogni dispositivo non identificato senza categoria manuale, finché l'utente non la imposta); la regola "firmware più vecchio dell'ultima versione nota" non è implementata.

**Motivazione**: tipo e gravità devono riflettere ciò che è stato davvero osservato. Per il firmware manca una fonte affidabile e gratuita dell'ultima versione per modello: una regola senza dati sarebbe una funzionalità finta.

### ADR-057 — Analisi alla chiusura della scansione; RESOLVED solo per ciò che la scansione ha coperto
**Decisione**: l'analisi gira nella transazione di chiusura della scansione, dopo il fingerprinting, solo sui dispositivi visti; non c'è rianalisi delle scansioni passate (`analysis_version` di docs/09 non implementato: le nuove CVE valgono dalla scansione successiva). Un finding di porta è risolto solo se il riepilogo `PORTSCAN` del dispositivo non è in pausa, ha la versione della lista porte del backend e il profilo della scansione, e la porta è nella lista di quel profilo; i finding UPnP solo se i dati del router sono stati letti; i finding di dispositivo se il dispositivo è stato visto.

**Motivazione**: "non rilevato" non significa "risolto" se la porta non è stata controllata (profilo diverso, host in pausa, router che rifiuta UPnP); i dati restano coerenti con la scansione che li ha prodotti. La rianalisi retroattiva cambierebbe lo storico senza una nuova osservazione.

### ADR-058 — Copia delle liste porte nel backend, verificata da test
**Decisione**: `resources/findings/portlists.json` è una copia di `agent/go-security-agent/internal/portscan/portlists.json`; un test fallisce se i due file differiscono e la risoluzione dei finding di porta richiede che la versione dichiarata dall'agent coincida con quella del backend.

**Motivazione**: il backend deve sapere quali porte un profilo ha controllato senza ricevere dall'agent l'elenco di tutte le porte chiuse; la copia evita un accoppiamento di build fra Go e Java, e il test impedisce che diverga. Con versioni diverse non si risolve nulla (scelta prudente).

### ADR-059 — Il punteggio usa il permesso `finding:read`
**Decisione**: `GET /homes/{id}/risk`, `/risk/history` e `/vulnerabilities` richiedono `finding:read`; nessun permesso `risk:read` dedicato.

**Motivazione**: il punteggio è un riassunto dei finding (il breakdown li elenca con titolo e dispositivo): chi può leggere il punteggio deve poter leggere i finding, e viceversa. Un permesso separato non proteggerebbe nulla in più e complicherebbe la matrice dei ruoli.

### ADR-060 — Giudizio separato dal livello di rischio
**Decisione**: oltre a `risk_level` (soglie di docs/09 §3.3) ogni snapshot ha `rating`: `LOW` → `EXCELLENT` solo con copertura ≥ 0.8 e punteggio non provvisorio, altrimenti `GOOD`; `MEDIUM` → `FAIR`; `HIGH` → `POOR`; `CRITICAL` → `CRITICAL`.

**Motivazione**: docs/09 vieta il giudizio "Ottimo" sotto 0.8 di copertura senza definire la scala. Un campo esplicito e salvato evita che la dashboard e l'app (M14) lo ricalcolino in modo diverso.

### ADR-061 — Input della copertura
**Decisione**:
- **Dispositivi visti**: dispositivi dell'inventario visti dalla scansione. **Analizzati**: quelli con riepilogo `PORTSCAN` non in pausa.
- **Tecniche**: ARP 0.4 e ICMP, mDNS, SSDP 0.2 ciascuna. Una tecnica fallisce con l'avviso `<TECNICA>_UNAVAILABLE`.
- **Integrazione router**: 1 solo se TR-064 o SNMP hanno restituito osservazioni.
- **Profilo `DEEP`**: non esiste; il suo peso resta nel modello.

**Motivazione**: sono dati già raccolti e affidabili; nessuna nuova richiesta all'agent. UPnP IGD non conta come integrazione, perché è dichiarato dal router e non configurato dal proprietario.

### ADR-062 — Doppio peso KEV mantenuto
**Decisione**: una CVE nel catalogo KEV alza già la gravità del finding di un livello (M10). Il motore applica comunque il fattore KEV 1.5 di docs/09, letto dal catalogo al momento del calcolo. Il limite di 45 punti per dispositivo resta.

**Motivazione**: una vulnerabilità sfruttata attivamente è il segnale più forte disponibile. Il doppio peso è voluto per ora e documentato; il limite per dispositivo evita che un singolo finding azzeri il punteggio. La taratura dei pesi è prevista in M18 con una nuova `engine_version`.

### ADR-063 — Snapshot `TRIAGE`, punteggio nullo per `DISCOVERY`, arrotondamento per difetto, pesi nel codice
**Decisione**:
- Un triage che cambia i finding conteggiati crea uno snapshot `TRIAGE`, con la scansione e la copertura dell'ultimo snapshot.
- Una scansione `DISCOVERY` salva uno snapshot con `score` nullo e `PORT_SCAN_REQUIRED`.
- Il punteggio è arrotondato per difetto.
- I pesi sono costanti di `RiskEngine` con `ENGINE_VERSION` registrata in ogni snapshot; non c'è un file di configurazione.

**Motivazione**: segnare un falso positivo deve cambiare subito il punteggio, senza riscrivere lo storico. Senza porte un punteggio sembrerebbe più sicuro del vero, ma la copertura resta utile. Arrotondando per eccesso un problema piccolo sparirebbe. Pesi tipizzati e versionati nel codice sono verificati dai test, e uno snapshot vecchio resta legato alla versione che lo ha prodotto.

### ADR-064 — Playwright per gli E2E della dashboard
**Decisione**: `@playwright/test` 1.65.1 come dipendenza di sviluppo (versione esatta). Gli E2E girano sulla build di produzione servita da un piccolo server statico (`e2e/serve.mjs`, senza dipendenze); ogni chiamata `/api` riceve dati `[MOCK]` intercettati nel browser. Due profili: desktop e mobile (Pixel 7). In locale si usa l'immagine `mcr.microsoft.com/playwright:v1.65.1-noble`, in CI `playwright install --with-deps chromium`.

**Licenza e costo**: Apache-2.0, gratuito; non entra nel bundle di produzione.

**Alternative**: Cypress (più pesante, profilo mobile meno fedele), solo test unitari (non verificano routing reale, layout e overflow su schermi piccoli). Gli E2E contro il backend reale restano nella verifica manuale e nella M18: qui verificano la dashboard senza toccare reti o dispositivi.

### ADR-065 — Panoramica con un endpoint aggregato e mappa di rete logica senza librerie
**Decisione**:
- `GET /api/v1/overview` restituisce le abitazioni visibili (`home:read`, con gli scope dell'utente) e, solo dove l'utente ha `finding:read` sull'abitazione, punteggio dell'ultimo snapshot calcolato, motivo dell'eventuale snapshot non calcolato, finding conteggiati per gravità, KEV, dispositivi e ultima scansione. Le cifre sono lette con una query per tipo di dato, non per abitazione.
- La mappa di rete è calcolata nel browser da dati già esposti (dispositivi, reti, breakdown dell'ultimo snapshot): una stella per rete autorizzata con il router al centro, anelli di dispositivi, SVG disegnato a mano. È dichiaratamente **logica**: il cablaggio e il Wi-Fi reali non sono osservabili dalla LAN. Una tabella ripete gli stessi dati.

**Motivazione**: una chiamata per abitazione dalla pagina non scala per gli installatori B2B. Il permesso sui dati di sicurezza resta quello della pagina del rischio (ADR-059). Una libreria di grafi (es. Cytoscape, D3) aggiungerebbe peso e un layout fisico che suggerirebbe una topologia che non conosciamo.

### ADR-066 — Apache PDFBox per i report PDF
**Decisione**: `org.apache.pdfbox:pdfbox` 3.0.8 (luglio 2026) nel backend. Il report è disegnato da codice (`ReportRenderer`) con i font PDF standard, senza HTML e senza font incorporati. Data di creazione e ID del documento sono fissati dai dati del report, così il risultato è deterministico.

**Licenza e costo**: Apache-2.0, gratuito; dipendenze transitive `pdfbox-io`, `fontbox` e `commons-logging`, tutte Apache-2.0.

**Alternative**:
- OpenPDF (LGPL/MPL) e openhtmltopdf (LGPL), con licenze meno semplici per un SaaS commerciale;
- JasperReports, troppo pesante;
- generazione nel browser, che non dà un documento uguale per tutti e non è riusabile dall'app (M14).

Con il disegno da codice, il test snapshot verifica testo e layout senza un motore di template.

**Limite**: i font standard coprono solo l'alfabeto latino (WinAnsi); gli altri caratteri sono sostituiti. Un font Unicode incorporato può essere aggiunto in seguito, con licenza OFL.

### ADR-067 — Alert e report nel database: consegne per utente, coda email a polling, PDF in `bytea`
**Decisione**:
- **Alert**:
  - creati nella transazione dell'evento, con deduplicazione affidata a un indice unico parziale e a `INSERT … ON CONFLICT`;
  - le consegne (`alert_deliveries`) sono decise alla creazione per utente e canale, secondo permessi e preferenze. Lo stato di lettura è per utente; i permessi sono ricontrollati in lettura.
- **Email**: messe in coda come righe `PENDING` e inviate da un job ogni 30 secondi, con 3 tentativi (5 e 15 minuti).
  - Il job legge gli id tra i tenant con una funzione `SECURITY DEFINER` e tratta ogni consegna nella transazione del suo tenant, come il reaper delle scansioni.
  - Un secondo job crea `AGENT_OFFLINE` dopo 15 minuti senza heartbeat.
- **Report**:
  - generati in background (virtual thread) dopo il commit della richiesta, e salvati in `reports.content` (`bytea`, massimo 10 MB) con SHA-256;
  - i testi di regole, gravità e categorie sono copiati dalla dashboard con uno script e verificati da un test.

**Motivazione**:
- **Database invece di broker o object storage**: nessun servizio in più da gestire o pagare per l'MVP su una VPS. L'email non parte se la transazione fallisce e sopravvive a un riavvio; le righe sono protette da RLS.
- **PDF in `bytea`**: pochi KB per report, backup già incluso nel `pg_dump`.
- **Destinatari decisi alla creazione**: permettono "una sola email per evento" e uno storico coerente.
- **Testi copiati**: con un unico testo per regola, dashboard, email e PDF dicono la stessa cosa.

**Rivedere quando**: volumi alti di email (code dedicate) o report numerosi e grandi (object storage S3-compatibile). Restano entrambi dietro `AlertJobs` e `ReportRepository`.

### ADR-068 — Dipendenze dell'app Flutter (M14)
**Decisione**: app in `mobile/shsc_app` con Flutter 3.44.0 / Dart 3.12 (immagine Docker `ghcr.io/cirruslabs/flutter`, nessuna installazione locale) e le dipendenze già previste da docs/01 §3 e docs/06:
- `flutter_riverpod` 3.5.0 (stato), `dio` 5.11.1 (HTTP), `go_router` 18.1.4 (navigazione);
- `flutter_secure_storage` 11.2.0 (refresh token in Keystore/Keychain, `this_device`, backup Android disattivato);
- `firebase_core` 5.2.0 e `firebase_messaging` 17.1.0 (push FCM);
- `intl` 0.20.2 e `flutter_localizations` (IT/EN con `gen-l10n`); `integration_test` (SDK) per i test su dispositivo.

**Licenze e costo**: BSD-3 (Flutter, `intl`, `firebase_*`), MIT (`riverpod`, `dio`, `go_router`), BSD-3 (`flutter_secure_storage`). FCM è gratuito; il progetto Firebase è del proprietario e non è creato dal codice.

**Alternative**: `http` invece di `dio` (niente interceptor per la rotazione del refresh token); `provider`/`bloc` invece di Riverpod (docs/01 indica già Riverpod); notifiche locali o polling invece di FCM (non arrivano ad app chiusa).

**Limiti**: `getToken`/`onTokenRefresh` sono deprecati in `firebase_messaging` 17 a favore di `register()`/`onRegistered` (Firebase Installation ID): restano finché l'invio HTTP v1 usato dal backend non è documentato con l'FID.

### ADR-069 — Autenticazione mobile e push FCM senza SDK Google nel backend
**Decisione**:
- **Login mobile**: `POST /auth/mobile/{login,refresh,logout}` con il refresh token nel body JSON e mai in cookie. Riusano sessioni, rotazione, rilevamento del riuso, blocco progressivo e audit del web; sono esclusi dal CSRF perché non leggono cookie e richiedono un token che solo l'app possiede.
- **Registrazioni push** (`push_devices`): legate alla sessione di login. Logout, revoca o scadenza fermano le notifiche senza passaggi aggiuntivi; l'app cancella comunque la registrazione al logout. Il token FCM non è mai restituito né scritto nei log.
- **Canale `PUSH`**: si aggiunge a `DASHBOARD` ed `EMAIL` con le stesse preferenze (predefinito da `MEDIUM`) e la stessa coda con ritentativi (ADR-067). Una consegna push nasce solo se FCM è configurato e l'utente ha un'app collegata.
- **Contenuto**: titolo dell'alert nella lingua del dispositivo e nome dell'abitazione; nei dati solo `alertId`, `homeId`, `type`. Nessun IP, nessuna evidenza.
- **Client FCM**: API HTTP v1 implementata con il JDK (`HttpClient`, firma RS256 dell'assertion OAuth del service account, token in cache). Nessuna dipendenza Google aggiunta. Disattivato senza `SHSC_FCM_PROJECT_ID` e `SHSC_FCM_CREDENTIALS_FILE`.

**Motivazione**: un cookie `SameSite=Strict` non è adatto a un client nativo, e docs/06 prevedeva già il body. Il Firebase Admin SDK porterebbe decine di dipendenze transitive per una sola chiamata HTTP. Legare il push alla sessione evita notifiche su un telefono da cui l'utente è uscito.

**Rivedere quando**: servono topic, invii in blocco o APNs diretto (valutare l'Admin SDK con un nuovo ADR).

### ADR-070 — Integrazione Home Assistant lato agent, in sola lettura; Matter tramite Home Assistant
**Decisione**:
- **Lato agent**: Home Assistant è nella LAN, quindi lo contatta l'agent (come i router, `secret_location = AGENT_LOCAL`). URL (solo IP letterale) e token di lunga durata sono salvati in `homeassistant.json`, protetto come la chiave dell'agent. Il backend non riceve mai token né URL completo. Le route `GET/POST /homes/{homeId}/integrations` previste in docs/05 non servono per Home Assistant e non sono state create.
- **Ambito**: l'IP deve appartenere alle reti autorizzate del job; il backend ricontrolla e scarta.
- **Sola lettura**: `GET /api/config` (solo `version`) e `POST /api/template` con un template Jinja che legge il registro dispositivi. Nessuna chiamata a servizi, nessuna WebSocket API.
- **Client HTTP standard Go**: niente proxy, niente redirect, limiti di tempo e dimensione, TLS ≥ 1.2 verificato. Nessuna nuova dipendenza.
- **Upload**: batch dedicato `homeAssistant`, uno per scansione; tabelle `scan_home_assistant` e `scan_gateway_devices` (V014, RLS).
- **Matter**: tramite l'integrazione Matter di Home Assistant del proprietario. Un controller proprio è scartato; mDNS passivo rimandato.

**Motivazione**: la REST API con token di lunga durata è il metodo ufficiale e documentato. `/api/template` restituisce il registro dispositivi in una sola richiesta, senza WebSocket né librerie. Tenere il token sull'agent evita di custodire nel cloud una credenziale che dà accesso alla casa.

**Alternative**: WebSocket API (`config/device_registry/list`: più completa, ma serve un client WebSocket, cioè una dipendenza o codice in più); `GET /api/states` (solo entità, niente dispositivi né produttori); token custodito dal backend (scartato: credenziale della casa nel cloud, e il backend non raggiunge la LAN).

**Rivedere quando**: `/api/template` cambia o viene limitato, servono aree o dati di sicurezza di Home Assistant stessa, oppure si aggiunge il discovery Matter via mDNS.

### ADR-071 — Assistente di sicurezza: provider LOCAL deterministico, Ollama opzionale, validazione delle risposte
**Decisione**:
- **Porta `AssistantProvider`**: `LOCAL` (predefinito) compone risposte deterministiche dai dati della casa, gratis e offline. `OLLAMA` (opzionale, `SHSC_ASSISTANT_PROVIDER=OLLAMA` + `SHSC_OLLAMA_URL`) chiama un LLM self-hosted con il `HttpClient` del JDK. Nessuna nuova dipendenza.
- **Solo dati del tenant**: punteggio (ultimo `risk_snapshots`), finding aperti e dispositivi letti con le query del report PDF (stessa RLS), con id `S1`, `F1…`, `D1…`. Testi provenienti dalla LAN ripuliti da caratteri di controllo e link, massimo 160 caratteri.
- **Validazione**: ogni risposta non LOCAL passa da `GroundingValidator`: citazioni esistenti e obbligatorie, nessun IP, CVE, link o punteggio assente dai dati. Se non passa, o il provider fallisce, si mostra la risposta LOCAL con `fallback=true`.
- **Nessuna azione**: i provider non hanno strumenti; le richieste di azione sono rifiutate con il rimando alla dashboard.
- **Nessuna memoria**: domande e risposte non sono salvate; l'audit `ASSISTANT_QUERY` registra provider, fallback, lunghezza della domanda e numero di citazioni, mai il testo.
- **Provider cloud** (es. Claude API): non incluso. Ha un costo e invierebbe dati della casa a terzi; servirà un ADR dedicato con l'SDK ufficiale e la decisione sui costi.

**Motivazione**: il vincolo "nessun servizio a pagamento" e la richiesta di risposte solo dai dati del tenant. Una risposta deterministica è verificabile al 100%; un LLM resta utile per domande libere, ma solo dietro una validazione che ne scarta le invenzioni.

**Alternative**: chiamare subito un LLM cloud (costo, privacy, dipendenza di rete); salvare le conversazioni (dati personali in più senza un requisito); dare strumenti all'LLM (contrario a "nessuna azione").

**Rivedere quando**: si decide un budget per un provider cloud, servono conversazioni multi-turno o le domande libere superano ciò che LOCAL copre.

### ADR-072 — Abbonamenti con Stripe Checkout/Billing Portal via REST, stato solo da webhook firmati; white label per piano
**Decisione**:
- **Nessun SDK Stripe**: tre chiamate REST form-encoded (`/v1/customers`, `/v1/checkout/sessions`, `/v1/billing_portal/sessions`) con il `HttpClient` del JDK. Niente redirect né proxy; nei log solo tipo e codice dell'errore Stripe. Nessuna nuova dipendenza.
- **Pagamento ospitato da Stripe**: la dashboard riceve solo l'URL di Checkout o del Portal, accettato solo se `https://checkout.stripe.com` o `https://billing.stripe.com`. Dati di carta e fatture restano in Stripe.
- **Stato solo da webhook**: firma `Stripe-Signature` HMAC-SHA256 verificata sul corpo grezzo, con tolleranza di 5 minuti. Eventi idempotenti (`stripe_webhook_events`), ordinati per `created` (`STALE` se più vecchi dell'ultimo applicato). Il tenant si ricava solo dal `customer` salvato al checkout, tramite `billing_lookup_tenant` (SECURITY DEFINER), mai da metadati o `client_reference_id`. Elaborazione in una transazione del tenant (RLS) con lock della riga della sottoscrizione. Dalla M18 anche `stripe_webhook_events` è sotto RLS (V017): il controllo di idempotenza avviene già nell'ambito del tenant del customer.
- **Piano effettivo**: `tenants.plan_code` = piano del Price se lo stato è `active`, `trialing` o `past_due` e il piano è ammesso per il tipo di tenant; altrimenti FREE. `past_due` dà la tolleranza durante i tentativi di Stripe solo se la sottoscrizione è già stata pagata almeno una volta (`has_paid`): un primo pagamento fallito a fine prova applica subito FREE. Il downgrade non cancella nulla: `PlanLimits` blocca solo le nuove risorse.
- **Doppio checkout (M18)**: checkout dello stesso tenant serializzati dal lock sulla riga della sottoscrizione; prima della nuova sessione si interroga Stripe (`GET /v1/subscriptions`, permesso Subscriptions in lettura) e si fanno scadere le Checkout Session aperte. Una seconda sottoscrizione arrivata comunque non sostituisce quella corrente non terminata (`IGNORED`, audit `duplicate=true`).
- **Prova gratuita**: `SHSC_STRIPE_TRIAL_DAYS` (0–730, predefinito 0), gestita da Stripe (`trial_period_days`, carta raccolta al checkout, `missing_payment_method=cancel`). Una sola prova per tenant: offerta finché il tenant non ha avuto una sottoscrizione (`trial_used`, V016). Un checkout abbandonato non la consuma.
- **Sicurezza operativa**: solo chiavi `sk_test_`/`rk_test_` salvo `SHSC_STRIPE_ALLOW_LIVE=true`; gli eventi `livemode` sono ignorati se non ammessi. Senza chiavi la funzione è disattivata. Nuovo permesso `billing:manage` (ORGANIZATION_ADMIN, CUSTOMER), solo a livello tenant.
- **White label**: `tenant_branding` (RLS), applicato solo se `plans.white_label` (PRO): header della dashboard (nome, `--primary`, logo come data URL compatibile con la CSP) e intestazione/creator dei PDF. Logo solo PNG/JPEG con magic bytes coerenti, header letto senza decodifica completa (max 2048×2048), niente SVG; servito con `nosniff` e CSP `sandbox`.

**Motivazione**: Checkout e Billing Portal tengono il progetto fuori dall'ambito PCI dei dati di carta e non richiedono UI di pagamento proprie. Usare il webhook come unica fonte evita che un redirect manipolato attivi un piano. Ricavare il tenant dal customer salvato impedisce a un evento di toccare un'altra organizzazione. L'SDK Java di Stripe sarebbe una dipendenza grande per tre chiamate.

**Alternative**: SDK `stripe-java` (dipendenza e aggiornamenti di versione API); Stripe Elements nella dashboard (più codice e più superficie PCI); attivare il piano al ritorno da Checkout (falsificabile); tenant dai metadati dell'evento (un metadato errato colpirebbe un altro tenant).

**Rivedere quando**: servono più prezzi per piano (mensile/annuale), quantità o fatturazione a consumo, un'area amministrativa dei piani, white label su e-mail e app mobile, oppure si passa a chiavi live.

### ADR-073 — Firma delle release dell'agent con Ed25519 della libreria standard Go
**Stato**: Proposta (M18)

**Decisione**: il manifest `SHA256SUMS` di ogni build dell'agent è firmato con Ed25519 dal comando `shsc-release-sign` (nuovo `cmd/` dell'agent, solo `crypto/ed25519` della libreria standard: nessuna nuova dipendenza). `build-agent.sh` firma se `SHSC_RELEASE_KEY_FILE` indica la chiave privata; altrimenti avvisa che la build non è firmata. La chiave privata resta offline (mai in git né nei container di build oltre al mount in sola lettura); la chiave pubblica è pubblicata con la documentazione. Il binario `shsc-release-sign` per Windows, Linux e macOS è incluso nella release per la verifica (`verify release.pub SHA256SUMS`, poi `sha256sum -c`).

**Motivazione**: l'utente installa l'agent con privilegi di rete nella propria LAN: deve poter verificare che i file vengano dal progetto. Authenticode e notarizzazione Apple richiedono certificati a pagamento, esclusi dal vincolo "nessun servizio a pagamento".

**Alternative**: minisign/cosign/GPG (nuovi strumenti esterni da installare per chi verifica); Authenticode/notarizzazione (a pagamento); solo SHA256SUMS (non protegge da un manifest sostituito insieme ai binari).

**Conseguenze**: Windows SmartScreen e macOS Gatekeeper continueranno ad avvisare sui binari non firmati con certificato di piattaforma. La verifica è manuale finché non esiste un aggiornamento automatico dell'agent.

**Rivedere quando**: c'è un budget per certificati di firma del codice o si introduce l'aggiornamento automatico dell'agent (che dovrà verificare la firma prima di installare).

### ADR-074 — Inventario per interfacce e storico degli indirizzi
**Stato**: Proposta (M19)

**Decisione**:
- **Interfacce**: nuova tabella `device_interfaces` (V018), un MAC per riga, unico nell'abitazione. L'identità di un dispositivo diventa "una delle sue interfacce"; `devices.mac` resta il primo MAC visto (compatibilità M8–M18). Una scansione unisce prima i gruppi di osservazioni i cui MAC appartengono allo stesso dispositivo, che viene aggiornato una sola volta con tutti gli indirizzi.
- **Storico indirizzi**: `device_addresses` registra ogni IPv4/IPv6 visto, con prima/ultima rilevazione, MAC e numero di scansioni. Ambito (privato, link-local, ULA, globale…) e tipo di identificativo IPv6 (EUI-64 o casuale) sono calcolati dal backend (`Addresses`), non memorizzati. "Attuale" = visto dall'ultima scansione del dispositivo.
- **Conservazione**: IPv6 globali con identificativo casuale (temporanei/privacy) eliminati se non visti da 30 giorni; al massimo 256 indirizzi per dispositivo (si eliminano i meno recenti).
- **EUI-64**: un indirizzo IPv6 visto senza MAC si unisce al dispositivo il cui MAC è contenuto nell'identificativo EUI-64, solo se quel MAC è visto nella stessa scansione o è già un'interfaccia nota dell'abitazione.
- **Unione mai automatica**: due dispositivi con lo stesso nome restano "probabilmente lo stesso dispositivo" (`probable_same_as`, ora per qualsiasi MAC, verso il dispositivo visto per primo). L'utente con `device:classify` conferma (`POST /devices/{id}/merge`: interfacce, indirizzi, osservazioni, porte, alert e finding non duplicati passano al dispositivo di destinazione, l'altro viene eliminato) oppure esclude la coppia (`same_as_dismissed`). Entrambe le azioni vanno nell'audit.
- **Ambito invariato**: si registrano solo indirizzi delle reti autorizzate; il filtro di ambito delle osservazioni non cambia.

**Motivazione**: un dispositivo dual-stack o con due schede (Ethernet + Wi-Fi) compariva come più dispositivi e gli indirizzi precedenti andavano persi. Un nome uguale non basta a dimostrare che due MAC siano lo stesso dispositivo, quindi la conferma resta all'utente.

**Alternative**: unione automatica per nome (rischio di unire dispositivi diversi); colonne aggiuntive su `devices` (nessuno storico); memorizzare ambito e tipo nel database (derivabili dall'indirizzo).

**Conseguenze**:
- L'unione non è reversibile: identificazioni, storico delle categorie, protocolli e finding duplicati del dispositivo rimosso si ricalcolano alla scansione successiva. La categoria manuale del dispositivo rimosso non viene copiata.
- Gli IPv6 globali (2000::/3) non vengono registrati, perché solo reti private, ULA e link-local sono autorizzabili (`NetworkRange`).

**Rivedere quando**: si decide di accettare gli IPv6 globali dei dispositivi già in ambito (raccolti in modo passivo, senza scansione), oppure serve "separare" un'unione.

### ADR-075 — IPv6 globali registrati in modo passivo
**Stato**: Proposta (M19, supera la conseguenza di ADR-074 sugli IPv6 globali)

**Decisione**: l'agent legge dalla propria tabella dei vicini gli indirizzi IPv6 globali (2000::/3) **non** in ambito e li allega, nel dettaglio `globalIpv6`, all'osservazione in ambito con lo stesso MAC (massimo 8 per MAC, 256 per scansione). Non diventano host, non vengono mai sondati, scansionati o contattati. Il backend li aggiunge allo storico indirizzi del dispositivo (massimo 8 per osservazione), con le regole di conservazione di ADR-074 (casuali eliminati dopo 30 giorni).

**Motivazione**: un dispositivo dual-stack usa spesso solo indirizzi globali; ignorarli rende incompleto l'inventario. La lettura della tabella dei vicini è passiva e non estende l'ambito autorizzato.

**Alternative**: autorizzare i prefissi globali come reti (estenderebbe l'ambito delle scansioni); ignorarli (inventario incompleto).

**Conseguenze**: un indirizzo globale compare solo se appartiene a un MAC già in ambito; `NetworkRange` continua a rifiutare i prefissi globali.

**Rivedere quando**: si vuole analizzare attivamente i servizi esposti su IPv6 globale (servirebbe un consenso esplicito e un limite di ambito diverso).

### ADR-076 — Stato dei campi di identità e origine delle fonti
**Stato**: Proposta (M20)

**Decisione**:
- Ogni candidato di un campo registra **fonte** (metodo), **affidabilità** (H/M/L), **origine** (l'informazione originaria) e se è **dichiarato dal dispositivo**. Lo stato del campo (`device_identifications.status`, V019) è:
  - **VERIFIED**: nessun conflitto e (una fonte dichiarata concorda, oppure ≥ 2 **origini distinte** con affidabilità H/M concordano), oppure valore confermato dall'utente;
  - **PROBABLE**: tutti gli altri casi, compreso ogni conflitto;
  - **UNKNOWN**: nessun valore (calcolato nella risposta, non memorizzato).
- Dichiarati: descrittore UPnP (produttore, modello, codice prodotto, firmware), TXT mDNS, IPP, autodescrizione del router (TR-064/SNMP), nomi annunciati via mDNS/NetBIOS, IP e MAC osservati direttamente (ARP/NDP/agent).
- Stessa origine: i nomi delle tabelle del router (TR-064, SNMP) e il DNS inverso derivano dallo stesso annuncio DHCP (`NAME_ANNOUNCEMENT`); i dati dall'OUI hanno origine `OUI` e affidabilità L. Le euristiche (L) non contano mai come conferma.
- Home Assistant: origine indipendente (`HOME_ASSISTANT`, M) ma non dichiarazione: da solo dà PROBABLE.
- **CPE** derivato da produttore e modello (`cpe:2.3:h:…`, componenti normalizzati ed escapati): sempre PROBABLE salvo conferma dell'utente. **Categoria**: PROBABLE, VERIFIED solo se impostata manualmente.
- **Conferme dell'utente** (`device_identity_confirmations`, `PUT /devices/{id}/identity`): prevalgono sulle scansioni, che non le sovrascrivono; il conflitto con le fonti resta visibile. **Nome personalizzato** (`devices.custom_name`, `PUT /devices/{id}/name`): mai modificato dalle scansioni.
- **Storico** (`device_identification_history`): ogni cambio di valore o di stato, con origine SCAN/USER, massimo 50 voci per campo.

**Motivazione**: il criterio M20 richiede 0 valori "Verificato" errati: due fonti che ripetono la stessa informazione non sono una conferma.

**Alternative**: stato derivato dalla sola confidenza (non distingue origini ripetute); CPE dal dizionario NVD (mapping IoT ambiguo, nessuna dipendenza nuova ora).

**Conseguenze**: molti campi restano PROBABLE o UNKNOWN (firmware spesso non esposto). Rimuovere una conferma riporta il valore delle fonti come PROBABLE fino alla scansione successiva.

**Rivedere quando**: si introduce il dizionario CPE NVD (M21) o SNMP con community inserita dall'utente.

### ADR-077 — Immagini dei dispositivi (M23)

**Decisione**:
- **Icona dichiarata dal dispositivo**: l'agent la scarica dalla descrizione UPnP del dispositivo (origine `UPNP`, fonte `DEVICE`), tabella `scan_device_icons`, poi adottata in `device_images`.
- **Ricerca SSDP unicast**: gli host trovati che non hanno risposto alla ricerca multicast vengono interrogati direttamente (`HOST: ip:1900`, massimo 256, solo IPv4 del target autorizzato, accettate solo le risposte degli indirizzi interrogati).
- **Foto dell'utente** (fonte `USER`, origine `UPLOAD`): mostrata prima dell'icona e mai sostituita da una scansione.
- **Sicurezza**:
  - accettati solo PNG e JPEG reali (verifica del contenuto, massimo 1 MB);
  - servite con `nosniff`, `Content-Security-Policy: default-src 'none'; sandbox`, ETag e cache privata;
  - le icone di indirizzi fuori dalle reti autorizzate vengono scartate.

**Motivazione**: riconoscere a colpo d'occhio i dispositivi senza servizi esterni.

**Conseguenze**:
- Le reti senza UPnP non producono icone (verificato sulla rete d'ufficio: 0 risposte): lì serve la foto caricata.
- Il frontend scarica le immagini con la sessione (blob → object URL), perché un `<img src>` non si autentica. Per questo la CSP della dashboard ammette `img-src … blob:` (solo immagini: gli script restano `'self'`). Senza, il browser blocca ogni immagine, cosa che i test unitari non rilevano.
- Verificato sulla rete reale: la TV LG ha risposto alla ricerca SSDP unicast e la sua icona (PNG 120×120) è comparsa in elenco e mappa.

### ADR-078 — Identificazione: registro OUI, regole TV/PC, mDNS unicast

**Decisione**:
- **Registro OUI IEEE**: senza il registro nessun produttore viene ricavato dal MAC.
  - La sincronizzazione resta manuale e riservata all'amministratore di piattaforma (`POST /api/v1/platform/oui/sync`).
  - Dietro un proxy TLS aziendale il download del backend fallisce, perché Java non si fida della CA del proxy. In quel caso si scaricano i 3 CSV pubblici con il trust store di sistema e si importano in `oui_entries`, con gli stessi vincoli del parser.
  - Non si installano certificati e non si disattiva la verifica TLS.
- **Ruleset `2026.11-3`**:
  - `tv.mdns-tv-os` (STRONG): piattaforma TV nel nome mDNS dichiarato, per esempio "webOS TV";
  - `tv.hostname-os` (MODERATE);
  - `desktop.netbios-pc-maker` (STRONG): nome NetBIOS più OUI di un produttore di PC, due indizi indipendenti. Esclusi i server (HPE) e le macchine virtuali (Microsoft).
- **mDNS unicast** (RFC 6762 §5.5): agli host trovati che non hanno risposto in multicast si chiede direttamente sulla porta 5353 il nome che si danno (PTR inverso in `.local`) e i servizi DNS-SD.
  - Vincoli: massimo 256 host, solo IPv4 del target, solo le risposte degli indirizzi interrogati.
  - Gli indirizzi aggiuntivi dichiarati non vengono attribuiti.

**Motivazione**: nella rete reale produttore, categoria e nome mancavano per quasi tutti i dispositivi. Con il registro, il produttore si ricava per tutti i MAC non casuali (36/36).

**Alternative**:
- assegnare il ruolo di amministratore di piattaforma all'utente via database (scartata: escalation di privilegi);
- fidarsi del proxy disattivando la verifica TLS (scartata).

**Conseguenze**:
- Telefoni VoIP, firewall e switch non hanno una categoria dedicata e restano "non identificati".
- I dispositivi che non dichiarano un nome restano senza nome: per quelli c'è il nome personalizzato.

**Rivedere quando**: si aggiungono categorie (VoIP, apparato di rete, server: fatto con ADR-079) o la sincronizzazione OUI pianificata.

### ADR-079 — Categorie Telefono VoIP, Apparato di rete, Server

**Decisione**:
- Nuove categorie: `VOIP_PHONE`, `NETWORK_DEVICE` (firewall, switch, access point) e `SERVER`. La migrazione V021 aggiorna i vincoli della categoria automatica e di quella manuale.
- Etichette e icone aggiunte in dashboard, app mobile e report.
- **Ruleset `2026.11-4`** (73 regole):
  - **Produttori monouso** (STRONG): produttori le cui schede di rete finiscono solo in un tipo di apparato.
    - VoIP: Yealink, Grandstream, Snom, Fanvil, Polycom, Htek.
    - Rete: Sophos, Fortinet, Palo Alto, WatchGuard, SonicWall, Netgate, Juniper, Aruba, Ruckus, Cambium.
    - È un'eccezione dichiarata a "l'OUI è solo un indizio debole": essendo una sola fonte, la confidenza resta al massimo MEDIA e la categoria PROBABILE.
    - I produttori generici, come TP-Link, restano indizi deboli.
  - **Server**:
    - nome NetBIOS da server (`server`, `srv`, `dc`, `hyperv`…) su una scheda di un produttore di server o di una macchina virtuale (STRONG);
    - hostname da server (MODERATE);
    - NetBIOS su scheda virtuale Microsoft o VMware (MODERATE).
    - Un nome da server prevale sulla regola "computer" (stessa scheda Dell, punteggio più alto).
  - **VoIP e rete da servizi e nomi**: servizio SIP, porte 5060/5061, hostname, titolo dell'interfaccia web.

**Motivazione**: nella rete reale la maggior parte dei dispositivi "non identificati" erano telefoni VoIP, firewall e server, per i quali non esisteva una categoria.

**Conseguenze**:
- Le scansioni successive ricalcolano la categoria.
- Le categorie manuali non vengono mai sovrascritte.
- Le app più vecchie mostrano queste categorie come "non identificato", grazie al fallback.

### ADR-080 — Doppioni senza MAC, ricalcolo dei dispositivi non visti, nuove regole

**Contesto**: nella rete reale c'erano due problemi.
- Alcuni IP comparivano due volte. In una scansione l'host aveva risposto solo al ping, senza MAC: diventava un dispositivo "per indirizzo", separato da quello con il MAC.
- I dispositivi non visti nelle ultime scansioni conservavano valori calcolati prima dell'import del registro OUI e delle nuove regole.

**Decisione**:
- **Doppioni**:
  - Un host visto senza MAC all'indirizzo attuale di un dispositivo noto con MAC è quel dispositivo. Eccezione: se quel MAC compare a un altro indirizzo nella stessa scansione, l'indirizzo è passato a un altro host.
  - Alla fine di ogni scansione, i dispositivi "solo indirizzo" con un gemello con MAC allo stesso indirizzo vengono uniti a quel gemello.
  - Restano separati quelli con dati inseriti dall'utente (categoria manuale, nome, valori confermati): per loro l'unione resta manuale (M19).
- **Ricalcolo**:
  - Alla fine di ogni scansione si ricalcolano i dispositivi non visti con un risultato superato: ruleset diverso, oppure MAC di produttore ancora senza produttore.
  - Si usano le osservazioni della loro ultima scansione, senza traffico, con al massimo 100 dispositivi per scansione.
  - Data e scansione dell'ultimo avvistamento non cambiano.
- **Dashboard**: i dispositivi assenti dall'ultima scansione sono marcati "non visto nell'ultima scansione".
- **Agent**: l'osservazione `SELF` porta il nome del PC dell'agent (solo la prima etichetta, caratteri validi, al massimo 63).
- **Ruleset `2026.11-5`**:
  - `desktop.netbios-workstation` (STRONG): un nome dichiarato via NetBIOS, esclusi i nomi da server, NAS e stampante. È una sola fonte, quindi al massimo MEDIA. NetBIOS non distingue un fisso da un portatile: la correzione è manuale.
  - `server.vm-netbios` passa a STRONG e si aggiunge `server.netbios-server-maker` (HPE, Supermicro): con un nome da postazione su queste schede c'è parità, quindi il dispositivo resta non identificato invece di essere preso per un PC.
  - `phone.android-private-mac` (STRONG): nome Android predefinito più MAC privato. Nuovo segnale `mac.randomized`.
  - `iot.oui-tuya` (STRONG): le schede Tuya sono solo in dispositivi smart. Una sola fonte, quindi MEDIA.

**Motivazione**: dati sbagliati (doppioni, valori vecchi) sono peggio di dati mancanti. Le nuove regole coprono i casi più frequenti della rete reale senza abbassare la soglia.

**Conseguenze**:
- Un ping senza ARP a un indirizzo riassegnato a un host nuovo (DHCP) viene attribuito al vecchio dispositivo finché ARP non risponde. È un caso raro: sulla stessa rete il ping passa comunque per ARP.
- I dispositivi "solo indirizzo" uniti perdono la loro cronologia di categoria; il dispositivo con il MAC tiene la sua.

### ADR-081 — Dispositivo ↔ persona (M24), parte 1: persone e nomi dei dispositivi
**Contesto**: il titolare vuole sapere in automatico chi usa ogni dispositivo. Dalla rete nessun protocollo trasmette il proprietario. L'unica informazione già raccolta che lo contiene è il nome che alcuni dispositivi annunciano ("iPhone-di-Marco", "Marcos-iPhone"). Fonti precise sono i sistemi in cui le persone fanno l'accesso (Active Directory, firewall con identificazione utenti): parte 2 e 3, da decidere a parte.

**Decisione (parte 1)**:
- Tabelle `home_people` (solo etichetta, origine, account facoltativo, `dismissed`) e `device_person_assignments` (`PROBABLE` / `CONFIRMED` / `REJECTED`, fonte, evidenza), migrazione V022 con RLS. Permessi nuovi `person:read` e `person:manage` (tutti i ruoli tranne `READ_ONLY`).
- **Automatico, a fine scansione** (stessa transazione, nessun traffico): si cerca un nome di persona nei nomi già raccolti del dispositivo (nome attuale, tutte le fonti del campo `HOSTNAME`, nome dato dall'utente) e nel nome del dispositivo in Home Assistant. Solo due forme: "dispositivo di/of Nome" e "Nome[s]-dispositivo", con una parola di dispositivo vicina e un elenco di parole generiche escluse ("Android", "DESKTOP", "admin"...). La persona viene creata se manca; l'associazione è `PROBABLE` con il nome come evidenza.
- **Decisioni dell'utente** (web): conferma (`CONFIRMED`), rimozione (`REJECTED`: non viene più riproposta), associazione manuale, nuova persona, rinomina, eliminazione. Una persona creata automaticamente ed eliminata resta solo come nome nascosto, così le scansioni non la ricreano; le sue associazioni sono cancellate.
- Unione di dispositivi (M19): le associazioni passano al dispositivo che resta.
- Audit di ogni azione dell'utente (`PERSON_*`, `DEVICE_PERSON_*`) senza il nome della persona. App: sola lettura.

**Motivazione**: solo dati già raccolti, nessuna inferenza da traffico, posizione o orari; un'associazione automatica non è mai presentata come certa.

**Conseguenze**:
- Nelle reti con nomi predefiniti (DESKTOP-xxx, Android_xxx) la parte 1 trova poche persone.
- Un nome di dispositivo può essere sbagliato o di un'altra persona (dispositivo prestato): per questo resta `PROBABLE` finché l'utente non conferma.
- Sul lavoro l'associazione dispositivo-dipendente richiede informativa GDPR e, per il controllo a distanza, le regole dell'art. 4 dello Statuto dei lavoratori: l'interfaccia lo ricorda, la decisione è del titolare.

### ADR-082 — Cancellazione delle scansioni e dell'inventario
**Contesto**: il titolare vuole cancellare le scansioni fatte. Non esisteva alcun modo: i dispositivi, i problemi, i report e lo storico del rischio puntano alle scansioni.

**Decisione**:
- Nuovo permesso `scan:delete` (V023): `SUPER_ADMIN`, `ORGANIZATION_ADMIN`, `CUSTOMER`. Non ai tecnici né ai `READ_ONLY`.
- `DELETE /scans/{id}`, solo per scansioni concluse (`409 SCAN_ACTIVE` altrimenti):
  - dispositivi e problemi visti solo da quella scansione vengono cancellati;
  - gli altri puntano alla scansione precedente o successiva in cui sono stati visti; i dispositivi la cui ultima scansione è stata cancellata vengono ricalcolati dalle osservazioni della nuova ultima scansione (stesso meccanismo di ADR-080, senza traffico);
  - report e punto di rischio di quella scansione vengono cancellati.
- `DELETE /homes/{homeId}/inventory` (`409 SCAN_ACTIVE` con una scansione in corso): cancella scansioni, dispositivi, problemi, persone (M24), report, storico del rischio e avvisi dell'abitazione. Restano abitazione, reti, autorizzazioni e agent.
- Entrambe in una transazione, irreversibili (nessuna copia di riserva), con audit `SCAN_DELETED` / `HOME_INVENTORY_CLEARED` e i soli conteggi.
- Dashboard: pulsanti nella cronologia delle scansioni con doppia conferma e avviso "definitivo".

**Conseguenze**:
- I dati inseriti dall'utente su un dispositivo visto solo dalla scansione cancellata (nome, foto, persone) vengono persi: l'avviso lo dice.
- L'app non offre la cancellazione (solo web).

## ADR-083 — Persone dagli accessi Active Directory e dal syslog Sophos (M24, parti 2–3)

**Contesto**: in ufficio i nomi dei dispositivi (DESKTOP-xxx, Android_xxx) non identificano chi li usa. L'utente ha scelto come fonti gli accessi al dominio Active Directory e le autenticazioni del firewall Sophos. Restano esclusi traffico attivo verso host non autorizzati, nuove dipendenze e servizi a pagamento.

**Decisione**:
- **Active Directory**:
  - l'agent Windows legge il registro Security del controller di dominio con l'API Event Log di sistema (`wevtapi.dll` via `golang.org/x/sys/windows`, già presente: nessuna nuova dipendenza);
  - sessione RPC in sola lettura, eventi 4624 e 4768 riusciti delle ultime 12 ore (configurabile fino a 72);
  - account dell'IT membro solo di "Event Log Readers", password su stdin, salvata con DPAPI;
  - letto solo a ogni scansione avviata dalla dashboard e solo se il controller di dominio è in una rete autorizzata.
  - Scartato LDAP `managedBy`: nuova dipendenza e dato spesso vuoto.
- **Sophos**:
  - listener syslog UDP passivo sull'agent (porta 5514 configurabile), che accetta solo pacchetti dall'IP del firewall configurato;
  - conserva in memoria solo IP ↔ utente (`user_name`/`user`, `src_ip`/`srcip`) per 12 ore, al massimo 4096 voci;
  - non interroga l'API del firewall: nessuna credenziale sul firewall.
- **Trasporto**:
  - nuova sezione `identities` del batch dei risultati, in un batch separato;
  - il backend tiene solo gli indirizzi delle reti autorizzate e li salva in `scan_identities` (V024, RLS), che si cancella con la scansione.
- **Associazione**:
  - a fine scansione, l'account sull'indirizzo di un dispositivo di quella scansione diventa una persona (`origin` DIRECTORY/FIREWALL, `external_key` = account in minuscolo) con associazione PROBABILE;
  - le decisioni dell'utente e le persone eliminate vengono rispettate, come in ADR-081.

**Conseguenze**:
- Uso lecito solo con informativa GDPR e nel rispetto dell'art. 4 dello Statuto dei lavoratori: la responsabilità è del titolare, la documentazione lo ricorda.
- IP condivisi o riassegnati possono dare associazioni sbagliate, per questo restano solo PROBABILI.
- Il syslog UDP non è autenticato.
- Le modifiche alla configurazione Sophos richiedono il riavvio dell'agent; la tabella è in memoria e si svuota al riavvio.
- Verificato solo con dati MOCK: nessun contatto con il dominio o il firewall reali (rete 192.168.1.0/24 non autorizzata per i test).
