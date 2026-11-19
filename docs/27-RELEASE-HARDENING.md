# 27 — Hardening e preparazione al rilascio (Milestone 18)

Verifiche pratiche della M18 sullo stack locale (`docker compose`, nginx su `https://localhost:8443`), correzioni fatte e checklist di rilascio. Dettagli dei singoli componenti nei documenti 12–26.

## 1. Threat model rivisto

| Asset / confine | Minaccia | Mitigazione | Verifica M18 |
|---|---|---|---|
| Account e sessioni | furto credenziali, brute force | Argon2id, lockout, rate limit `/api/v1/auth/` 30 r/min (burst 20), refresh token ruotati e revocabili | 429 dopo il burst (§2); **MFA assente** (criticità residua) |
| Dati tra tenant | accesso cross-tenant | RLS PostgreSQL su 43 tabelle + controlli di servizio | `DatabaseBaselineTest` ha trovato `stripe_webhook_events` (M17) senza RLS: corretto con V017; test di isolamento e matrice ruoli verdi (§3) |
| API pubblica | abuso, DoS applicativo | `shsc_api` 20 r/s (burst 40), body ≤ 4 MB, webhook ≤ 256 KB | 429 e 413 (§2) |
| Agent ↔ server | job falsificati, agent rubato | job firmati, identità agent revocabile, nessuna porta in ingresso | test agent Go |
| Distribuzione agent | binari manomessi | `SHA256SUMS` firmato Ed25519 (ADR-073), verifica con `shsc-release-sign` | firma valida, file manomesso rifiutato (§4) |
| Stripe | webhook falsi, doppio addebito | firma HMAC + tolleranza, idempotenza per event id, lock + controllo su Stripe al checkout, seconda sottoscrizione ignorata | `BillingIntegrationTest` 3/3; **mai provato con account Stripe reale** |
| Feed vulnerabilità | feed alterati o non raggiungibili | solo HTTPS, nessun dato utente inviato, errori isolati per feed | test feed reali (§5) |
| Scansioni | scansione di reti non autorizzate | solo reti dichiarate e autorizzate, nessun exploit o credenziale di default | **non provato su LAN reale** (§6) |
| Backup | perdita dati | `backup-db.sh` + `restore-db.sh verify` | drill di ripristino superato (§7); copia off-site non automatizzata |
| Actuator / interni | information disclosure | `/actuator/` 404 via nginx, solo `health` esposto come `/healthz` | §2 |

## 2. Pen-test interno (non distruttivo)

Eseguito solo contro lo stack locale, senza exploit, brute force o DoS.

| Controllo | Esito |
|---|---|
| Header di sicurezza (HSTS, CSP restrittiva, `X-Frame-Options: DENY`, `nosniff`, COOP, Referrer/Permissions-Policy) su statico e API | ✅ presenti |
| HTTP → HTTPS | ✅ 301 |
| TLS 1.0 / 1.1 | ✅ rifiutati; TLS 1.2 / 1.3 accettati |
| `/actuator/`, `/actuator/env`, `/actuator/health` | ✅ 404; `/healthz` restituisce solo `{"status":"UP"}` e i gruppi |
| API protette senza token (`/homes`, `/billing/subscription`, `/admin/tenants`, `/users/me`) | ✅ 401 `application/problem+json` |
| Rate limit API: 200 richieste concorrenti | ✅ 47 servite, 153 → 429 |
| Rate limit auth: 60 `POST /auth/refresh` | ✅ 27 → 403 (nessun cookie), 33 → 429 |
| Webhook Stripe senza chiavi configurate | ✅ 404 (billing disattivato) |
| Webhook con body da 300 KB | ✅ 413 da nginx |

## 3. Regressioni

| Componente | Esito |
|---|---|
| Backend, suite completa (unit + integrazione con Testcontainers, compresi isolamento tra tenant e matrice ruoli) | primo giro: 1 fallimento (`DatabaseBaselineTest`) → corretto con V017; suite completa rieseguita dopo V017: ✅ 216 eseguiti, 0 fallimenti, 0 errori, 1 saltato (test opzionale dei feed reali) |
| Frontend Angular | 28 file, 115/115 |
| Agent Go | `go vet` e `go test ./...` OK (dentro `build-agent.sh`) |
| App Flutter | `flutter analyze` nessun problema, `flutter test` 15/15 |

## 4. Firma delle release dell'agent

`SHSC_RELEASE_KEY_FILE=<release.key> infrastructure/scripts/build-agent.sh` esegue `go vet`, `go test`, compila 7 target dell'agent e 3 di `shsc-release-sign`, scrive e firma `SHA256SUMS`. Verificato con una chiave usa e getta: `verify` OK, `sha256sum -c` OK, `SHA256SUMS` alterato → "signature NOT valid", exit 1.

Per il rilascio: generare la chiave definitiva offline (`shsc-release-sign keygen`), pubblicare `release.pub` sul sito e nella guida utente, non mettere mai `release.key` in git o in CI non protetta. La firma Authenticode/notarizzazione macOS non è prevista (servizi a pagamento).

## 5. Feed vulnerabilità reali

`test-backend.sh -Dshsc.live-feeds=true -Dtest=VulnerabilityLiveFeedTest` scarica NVD (finestra di 7 giorni), KEV e EPSS reali e controlla volumi minimi e `CVE-2024-6387`. Test opzionale: non gira nella suite normale.

Esecuzione M18 (19/11/2026): ✅ 1/1 in 333 s — NVD 770 CVE per 12 prodotti CPE (0 scartate), KEV 1786, EPSS 770, nessun feed fallito. La sync NVD senza API key è lenta (limite pubblico di NVD): in produzione impostare la chiave NVD gratuita (`SHSC_NVD_API_KEY`).

## 6. Scansioni su dispositivi reali

Non eseguite: l'host di sviluppo è su una rete non autorizzata e l'unica rete autorizzata per i test (`172.20.204.0/22`) contiene solo macchine virtuali. Discovery, porte, servizi e matching CVE sono coperti dai test con dati MOCK e dalle prove E2E delle milestone 7–10. **Da eseguire prima del rilascio** su una rete di proprietà con autorizzazione scritta.

## 7. Backup e ripristino

- `infrastructure/scripts/backup-db.sh`: `pg_dump` custom con retention, in `backups/`.
- `infrastructure/scripts/restore-db.sh verify <dump>`: ripristino in un container PostgreSQL usa e getta senza rete, ruoli ricreati dal dump, controllo di versione Flyway, migrazioni fallite, tabelle, tabelle RLS, tenant e utenti; il container viene rimosso.
- `restore-db.sh live <dump>`: ripristino sul database in uso, con conferma digitando il nome del database (backend fermo).

Drill M18: primo drill su un dump del 18/11, precedente a V017 → Flyway V16, 42 tabelle RLS, coerente con il database di allora. Corretto lo script, che cercava le tabelle nello schema `public` invece di `shsc`. Ripetuto il 19/11 con un dump nuovo (278 KB) dopo V017 → ripristino OK, Flyway V17 (uguale al database live), 0 migrazioni fallite, 55 tabelle, 43 con RLS, 14 tenant e 17 utenti.

Su Windows con Git Bash eseguire gli script con `MSYS_NO_PATHCONV=1`, altrimenti i path dentro il container vengono convertiti.

Da fare in produzione: copia cifrata off-site dei dump (non automatizzata) e drill di ripristino periodico.

## 8. Monitoraggio

- `/healthz` (pubblico, solo stato) e healthcheck Docker su tutti i servizi.
- Log del backend in formato ECS JSON (`SHSC_LOG_FORMAT=ecs`) su stdout, pronti per un collettore (Loki, Elastic, ecc.); audit log applicativo nel database.
- Eventi da sorvegliare: 5xx, 429 in aumento, errori di sync dei feed, webhook Stripe `FAILED`, log `second Stripe subscription`, agent non più in heartbeat.
- Non incluso: stack di metriche e alerting (Prometheus/Grafana). Scelta del collettore rimandata al deploy.

## 9. Checklist di rilascio

| # | Voce | Stato |
|---|---|---|
| 1 | Regressioni backend, frontend, agent, Flutter verdi | ✅ (§3) |
| 2 | Pen-test interno non distruttivo | ✅ |
| 3 | Threat model rivisto | ✅ |
| 4 | Firma release agent | ✅ (chiave definitiva da generare offline) |
| 5 | Backup e drill di ripristino | ✅ (off-site da configurare) |
| 6 | Feed NVD/KEV/EPSS reali | ✅ |
| 7 | Doppio checkout Stripe | ✅ corretto e testato con Stripe simulato |
| 8 | Stripe in test mode con account reale | ❌ richiede le chiavi di test del titolare |
| 9 | Scansione su LAN reale autorizzata | ❌ richiede accesso a una rete autorizzata |
| 10 | App mobile su dispositivo e FCM reale | ❌ richiede dispositivo e progetto Firebase |
| 11 | MFA | ❌ non implementata: dichiarata nella guida utente |
| 12 | Segreti di produzione (JWT, firma job, Stripe, SMTP) generati e fuori da git | da fare al deploy |
| 13 | Certificato TLS pubblico (non self-signed) | da fare al deploy |
| 14 | Guida utente | ✅ `docs/28-USER-GUIDE.md` |
