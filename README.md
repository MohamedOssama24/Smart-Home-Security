# Smart Home Security Check

Piattaforma SaaS per l'analisi della sicurezza delle reti domestiche e dei dispositivi IoT (B2C e B2B): un **agent locale** individua e analizza i dispositivi della rete autorizzata, il **backend** classifica, rileva rischi e vulnerabilità e calcola un **Security Score** spiegabile, consultabile da **dashboard web** e **app mobile**.

> Stato: **Milestone 4 (utenti, organizzazioni, clienti, abitazioni, reti, limiti FREE)** completata, in revisione. Vedi [PROJECT_STATUS.md](PROJECT_STATUS.md).
> Nell'MVP **tutte le scansioni sono avviate manualmente** dall'utente.

## Stack
Angular 22 · Java 21 + Spring Boot 4.1 · PostgreSQL 18 · Go 1.27 (agent) · Flutter · Docker Compose + Nginx.

## Avvio rapido (sviluppo)
Requisito: Docker Desktop. Java, Node e Go **non** sono necessari in locale: build e test girano in container.

```bash
cp .env.example .env        # sostituire ogni CHANGE_ME (openssl rand -base64 32)
sh infrastructure/scripts/generate-jwt-key.sh   # valore per SHSC_JWT_PRIVATE_KEY in .env
docker compose --profile dev up -d --build      # --profile dev avvia anche Mailpit
```
Aprire `https://localhost` (o la porta `SHSC_HTTPS_PORT` impostata; in questo caso aggiornare anche `SHSC_PUBLIC_BASE_URL`, usato nei link delle email). In sviluppo il certificato è self-signed (`SHSC_TLS_SELF_SIGNED=true`). Le email di verifica e reset arrivano in Mailpit: `http://127.0.0.1:8025`.

Collegare un agent: dalla pagina di una casa generare un codice di enrollment, salvarlo in `token.txt` ed eseguire
`shsc-agent enroll --api https://localhost:8443 --token-file token.txt --ca-file dev-ca.pem`. Il file `dev-ca.pem` serve solo con il certificato self-signed; si ottiene con `docker compose exec nginx cat /etc/nginx/tls/fullchain.pem`.

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
| [Decisioni tecniche](TECHNICAL_DECISIONS.md) | ADR |

## Struttura repository (prevista da Milestone 2)
```
frontend/angular-dashboard/   backend/spring-boot-api/   agent/go-security-agent/
mobile/flutter-app/           database/migrations/       infrastructure/{docker,nginx,scripts}/
docs/  tests/  docker-compose.yml  .env.example
```

## Uso responsabile
Lo strumento analizza **solo reti di cui l'utente è proprietario o per cui è autorizzato**, solo indirizzi privati, senza exploit, brute force, credenziali predefinite né accesso a flussi video.
