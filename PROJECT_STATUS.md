# Project Status

**Ultimo aggiornamento**: 16/11/2026
**Posizione**: `C:\Users\mohamed\Desktop\smart-home-security-check` (repository git dedicato, branch `main`, nessun commit ancora)
**Milestone corrente**: 4 — Utenti, organizzazioni, clienti, abitazioni e reti → **COMPLETATA, in attesa di approvazione**
**Prossima milestone**: 5 (vedi `docs/11-ROADMAP-CHECKLIST.md`) — non iniziata

## Milestone
| # | Milestone | Stato |
|---|---|---|
| 1 | Analisi e architettura | ✅ Completata |
| 2 | Infrastructure & Docker | ✅ Completata |
| 3 | Autenticazione, sessioni, RBAC, identità agent | ✅ Completata e approvata |
| 4 | Utenti, organizzazioni, clienti, homes, reti, limiti piano FREE | ✅ Completata (in revisione) |
| 5–18 | vedi `docs/11-ROADMAP-CHECKLIST.md` | ⬜ Da iniziare |
| F | Scan Scheduler automatico | 🚫 Fuori MVP (solo predisposto) |

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
- Backend: **123/123** (Testcontainers, PostgreSQL 18 con RLS), regressione M2/M3 inclusa.
- Frontend: **73/73**; build di produzione OK.
- Agent Go: gofmt, vet, `go test -race` OK (19 test).
- Stack dev: migrazione V004 applicata sul DB esistente; smoke test (401 senza autenticazione, `/accept-invitation` 200, accettazione invito senza CSRF 403).

### Problemi riscontrati e risolti
- Text block Java: lo stripping degli spazi produceva SQL come `RETURNINGid` / `updated_atFROM` in HomeRepository e CustomerRepository → spazio esplicito.
- Spec frontend: richiesta token non presente per utenti senza `agent:enroll`; input di test non validi → corretti.

### Limiti noti
- Limite agent per abitazione rimandato alla M5.
- Le assegnazioni di ruolo rifiutate non sono registrate in audit.
- Tenant di sviluppo esistenti possono superare i limiti FREE (i limiti valgono solo per le nuove creazioni).
- Gateway e interfaccia delle reti arriveranno con le reti rilevate dall'agent.
- Verifica manuale della UI M4 nel browser non ancora eseguita.

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
