# Smart Home Security Check

Piattaforma SaaS per l'analisi della sicurezza delle reti domestiche e dei dispositivi IoT (B2C e B2B): un **agent locale** individua e analizza i dispositivi della rete autorizzata, il **backend** classifica, rileva rischi e vulnerabilità e calcola un **Security Score** spiegabile, consultabile da **dashboard web** e **app mobile**.

> Stato: **M1–M18 completate e approvate**; prima del rilascio pubblico restano le prove con Stripe reale, LAN reale e dispositivo mobile. Vedi [PROJECT_STATUS.md](PROJECT_STATUS.md).
> Nell'MVP **tutte le scansioni sono avviate manualmente** dall'utente.

## Stack
Angular 22 · Java 21 + Spring Boot 4.1 · PostgreSQL 18 · Go 1.27 (agent) · Flutter · Docker Compose + Nginx.

## Avvio rapido (sviluppo)
Requisito: Docker Desktop. Java, Node e Go **non** sono necessari in locale: build e test girano in container.

```bash
cp .env.example .env        # sostituire ogni CHANGE_ME (openssl rand -base64 32)
sh infrastructure/scripts/generate-jwt-key.sh   # valore per SHSC_JWT_PRIVATE_KEY in .env
sh infrastructure/scripts/generate-job-signing-key.sh   # valore per SHSC_JOB_SIGNING_KEY in .env
docker compose --profile dev up -d --build      # --profile dev avvia anche Mailpit
```
Aprire `https://localhost` (o la porta `SHSC_HTTPS_PORT` impostata; in questo caso aggiornare anche `SHSC_PUBLIC_BASE_URL`, usato nei link delle email). In sviluppo il certificato è self-signed (`SHSC_TLS_SELF_SIGNED=true`). Le email di verifica e reset arrivano in Mailpit: `http://127.0.0.1:8025`.

Collegare un agent: dalla pagina di una casa generare un codice di enrollment, salvarlo in `token.txt` ed eseguire
`shsc-agent enroll --api https://localhost:8443 --token-file token.txt --ca-file dev-ca.pem`. Il file `dev-ca.pem` serve solo con il certificato self-signed; si ottiene con `docker compose exec nginx cat /etc/nginx/tls/fullchain.pem`.
Poi, da un prompt amministratore (o con `sudo`), `shsc-agent service install` registra e avvia il servizio; `shsc-agent diagnose` mostra capabilities, interfacce, coda locale e raggiungibilità del backend. Dettagli in [14 Agent runtime](docs/14-AGENT-RUNTIME.md).

| Comando | Cosa fa |
|---|---|
| `bash infrastructure/scripts/test-backend.sh` | test backend (JDK 21 + Testcontainers PostgreSQL 18) |
| `cd frontend/angular-dashboard && npx ng test` | test frontend (Vitest) — oppure in container `node:24-alpine` |
| `bash infrastructure/scripts/build-agent.sh` | vet, test e cross-compile dell'agent in `agent/go-security-agent/bin/` |
| `bash infrastructure/scripts/backup-db.sh` | backup PostgreSQL in `./backups` con retention |
| `docker compose down` | ferma lo stack (i dati restano nel volume `postgres-data`) |

## Documentazione
| Documento | Contenuto |
|---|---|
| [01 Architettura](docs/01-ARCHITECTURE.md) | analisi repository, componenti, moduli, deployment |
| [02 Scansione manuale](docs/02-MANUAL-SCAN-WORKFLOW.md) | flusso, stati, profili, predisposizione scheduler |
| [03 Protocollo agent](docs/03-AGENT-PROTOCOL.md) | enrollment, autenticazione, heartbeat, job, coda offline, update |
| [04 Database](docs/04-DATABASE.md) | schema, RLS, indici, retention |
| [05 API](docs/05-API.md) | endpoint `/api/v1` |
| [06 Sicurezza, auth, tenancy](docs/06-SECURITY-AUTH-TENANCY.md) | JWT, MFA, RBAC, controlli, limiti etici |
| [07 Discovery e fingerprinting](docs/07-DISCOVERY-FINGERPRINTING.md) | ARP/ICMP/mDNS/SSDP/router, classificazione, confidenza |
| [08 Port scanning](docs/08-PORT-SCANNING-SERVICES.md) | TCP/UDP, service & protocol detection |
| [09 Analisi e rischio](docs/09-SECURITY-ANALYSIS-RISK.md) | finding, CVE/KEV, Security Score |
| [10 Rischi e limitazioni](docs/10-RISKS-LIMITATIONS.md) | |
| [11 Roadmap e checklist](docs/11-ROADMAP-CHECKLIST.md) | milestone, DoD, strategia test |
| [12 Autenticazione (M3)](docs/12-AUTHENTICATION.md) | architettura auth, endpoint, tabelle, flussi login/refresh ed enrollment agent, test di sicurezza |
| [13 Utenti, organizzazioni, reti (M4)](docs/13-USERS-ORGANIZATIONS-NETWORKS.md) | utenti e inviti, ambiti, clienti, abitazioni, reti autorizzate, limiti FREE, API |
| [14 Agent runtime (M5)](docs/14-AGENT-RUNTIME.md) | comandi, servizio di sistema, protezione chiavi, heartbeat, revoca, coda locale ed eventi, autodiagnosi capabilities |
| [15 Scansioni manuali (M6)](docs/15-MANUAL-SCANS.md) | macchina a stati, job firmati, long polling, lease e reaper, risultati idempotenti, discovery ARP, API e dashboard |
| [16 Network discovery (M7)](docs/16-NETWORK-DISCOVERY.md) | ICMP, mDNS, SSDP/UPnP+IGD (anti-SSRF), NetBIOS, rDNS, IPv6 NDP, integrazioni router TR-064/SNMP con credenziali del proprietario |
| [17 Fingerprinting (M8)](docs/17-DEVICE-FINGERPRINTING.md) | inventario dispositivi, registro OUI IEEE (sync manuale), regole e punteggi, affidabilità per campo, MAC randomizzati, classificazione manuale e storico, OS di base |
| [18 Porte e servizi (M9)](docs/18-PORT-SCANNING.md) | profili QUICK/STANDARD, TCP connect con limiti, probe UDP sicure, identificazione servizi in sola lettura (banner, HTTP, TLS, RTSP OPTIONS, SMB NEGOTIATE, ONVIF, IPP), protocolli rilevati, nuovi indizi di classificazione |
| [19 Analisi di sicurezza (M10)](docs/19-SECURITY-ANALYSIS.md) | regole di finding versionate, ciclo di vita e deduplicazione, triage, sync manuale NVD/KEV/EPSS, matching CVE conservativo, pagina "Problemi di sicurezza" |
| [20 Motore di rischio (M11)](docs/20-RISK-ENGINE.md) | punteggio 0–100 spiegabile, copertura e punteggio provvisorio, snapshot con breakdown e delta, ricalcolo dopo il triage, pagina "Punteggio di sicurezza" |
| [21 Dashboard (M12)](docs/21-DASHBOARD.md) | panoramica delle abitazioni con il punteggio, vulnerabilità note, mappa di rete logica, menu responsive, E2E Playwright |
| [22 Alert e report (M13)](docs/22-ALERTS-REPORTS.md) | alert con deduplicazione e preferenze, email SMTP con ritentativi, report PDF IT/EN deterministici, pagine Avvisi e Report |
| [23 App mobile (M14)](docs/23-MOBILE-APP.md) | app Flutter: login con refresh token nel body, dashboard, dispositivi, scansione manuale, avvisi, push FCM legato alla sessione |
| [24 Integrazioni (M15)](docs/24-INTEGRATIONS.md) | Home Assistant in sola lettura dall'agent (token sull'agent, solo nell'ambito), inventario Zigbee/Z-Wave/Matter/Thread/BLE, valutazione Matter |
| [25 Assistente IA (M16)](docs/25-AI-ASSISTANT.md) | assistente di sicurezza in sola lettura: risposte solo dai dati della casa con citazioni, provider LOCAL (predefinito) o Ollama, validazione anti-allucinazione |
| [26 SaaS e white label (M17)](docs/26-SAAS-BILLING.md) | piani FREE/PLUS/PRO, Stripe Checkout e Billing Portal, webhook firmati e idempotenti, isolamento tra tenant, white label in dashboard e PDF |
| [27 Hardening e rilascio (M18)](docs/27-RELEASE-HARDENING.md) | threat model rivisto, pen-test interno, firma release agent, backup/ripristino, monitoraggio, checklist di rilascio |
| [28 Guida utente (M18)](docs/28-USER-GUIDE.md) | account, agent e verifica firma, scansioni, risultati, app, integrazioni, abbonamento |
| [Decisioni tecniche](TECHNICAL_DECISIONS.md) | ADR |

## Struttura repository (prevista da Milestone 2)
```
frontend/angular-dashboard/   backend/spring-boot-api/   agent/go-security-agent/
mobile/flutter-app/           database/migrations/       infrastructure/{docker,nginx,scripts}/
docs/  tests/  docker-compose.yml  .env.example
```

## Uso responsabile
Lo strumento analizza **solo reti di cui l'utente è proprietario o per cui è autorizzato**, solo indirizzi privati, senza exploit, brute force, credenziali predefinite né accesso a flussi video.
