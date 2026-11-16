# 01 — Architettura di sistema

> Milestone 1 · Stato: **PROPOSTA — in attesa di approvazione**

## 1. Analisi del repository esistente (16/11/2026)

| Verifica | Risultato |
|---|---|
| Contenuto di `smart-home-security-check/` | **Vuoto**. Nessun codice esistente da preservare. Progetto greenfield. |
| Controllo versione | In origine la cartella era dentro `Desktop\lavoro` (repository git `webmedica/terapANGULAR`). **Risolto in Milestone 2**: progetto spostato in `C:\Users\mohamed\Desktop\smart-home-security-check` con repository git dedicato (branch `main`). Nota: anche `C:\Users\mohamed` è un repository git (`progetto-d-esame`); il repository annidato del progetto è indipendente (vedi ADR-001). |

### Toolchain presente sulla macchina di sviluppo

| Strumento | Versione rilevata | Target progetto | Azione |
|---|---|---|---|
| Java | 17.0.7 | **21 LTS** | Installare JDK 21 (Temurin). |
| `JAVA_HOME` | punta a `jdk-11.0.10` **inesistente** | JDK 21 | Correggere: oggi Maven non parte. |
| Maven | 3.8.1 | 3.9.x (o Maven Wrapper) | Usare `./mvnw` nel progetto. |
| Node.js | 18.16.0 (EOL) | **22 LTS** o 24 LTS | Aggiornare (Angular recente non supporta Node 18). |
| Angular CLI | 16.0.2 | ultima stabile (≥ 21) | Usare `npx @angular/cli@<versione>` per progetto, non globale. |
| Go | **assente** | ≥ 1.25 | Installare. |
| Flutter / Dart | **assenti** | ultima stable 3.x | Installare (serve solo dalla Milestone 14). |
| Docker / Compose | 27.5.1 / v2.32.4 | ok | — |
| psql | assente | non necessario | PostgreSQL gira in Docker. |

Le versioni esatte sono fissate in Milestone 2 (ADR-003). Build e test girano **dentro container Docker** (ADR-015), quindi la toolchain locale non blocca lo sviluppo; installarla resta utile per l'IDE.

## 2. Vista d'insieme

```
                       ┌────────────────────────── CLOUD (SaaS) ──────────────────────────┐
 ┌──────────────┐ HTTPS│ ┌────────┐   ┌──────────────────────────────────────────────┐    │
 │ Angular      ├──────┼─► Nginx  ├───►  Spring Boot API (monolite modulare)          │    │
 │ Dashboard    │      │ │ TLS,   │   │  identity · tenancy · homes · agents · scans │    │
 └──────────────┘      │ │ rate   │   │  inventory · fingerprinting · analysis       │    │
 ┌──────────────┐ HTTPS│ │ limit  │   │  vulnintel · risk · alerts · reports         │    │
 │ Flutter App  ├──────┼─►        │   │  billing · integrations · ai · audit         │    │
 └──────────────┘      │ └───▲────┘   └───────┬───────────────┬───────────┬─────────┘    │
                       │     │                │               │           │              │
                       │     │         ┌──────▼─────┐  ┌──────▼───┐ ┌─────▼──────────┐   │
                       │     │         │ PostgreSQL │  │ SMTP/FCM │ │ NVD · CISA KEV │   │
                       │     │         │ (RLS)      │  │ Stripe   │ │ (feed sync)    │   │
                       │     │         └────────────┘  └──────────┘ └────────────────┘   │
                       └─────┼────────────────────────────────────────────────────────────┘
                             │ HTTPS in USCITA dall'agent (nessuna porta aperta in casa)
 ┌───────────────────────────┼──────────── RETE DOMESTICA AUTORIZZATA ───────────────────┐
 │                  ┌────────┴──────────┐                                                 │
 │                  │ Go Security Agent │──ARP/ICMP/mDNS/SSDP/TCP/UDP──► dispositivi LAN  │
 │                  │ (servizio OS)     │──UPnP IGD / TR-064 / SNMP───► router (se autor.)│
 │                  └───────────────────┘                                                 │
 └─────────────────────────────────────────────────────────────────────────────────────────┘
```

Flusso: **Utente → Dashboard → Backend → Scan Request → Agent → Discovery locale → Raccolta evidenze → Backend (analisi) → PostgreSQL → Dashboard.**

### Principio guida: *l'agent è il sensore, il backend è il cervello*
- L'**agent** raccoglie fatti osservabili (osservazioni + evidenze grezze, strutturate) ed esegue solo i controlli che richiedono accesso alla LAN (es. handshake TLS, banner, SMB negotiate, mappature UPnP).
- Il **backend** è la fonte di verità per classificazione, confidenza, finding, match CVE e Security Score. Così le regole si aggiornano centralmente, sono coerenti tra agent di versioni diverse, e una scansione può essere **ri-analizzata** senza ripetere la scansione.

## 3. Componenti

| # | Componente | Tecnologia | Responsabilità |
|---|---|---|---|
| 1 | Angular Dashboard | Angular (standalone, signals), Angular Material, Transloco (IT/EN), ECharts, Cytoscape.js | UI web B2C/B2B |
| 2 | Backend API | Java 21, Spring Boot, Spring Security, Spring Data JPA, Flyway, springdoc-openapi | API REST `/api/v1`, orchestrazione scansioni, analisi |
| 3 | Database | PostgreSQL 18 | Persistenza, Row-Level Security, migrazioni Flyway |
| 4 | Local Agent | Go ≥ 1.25, binario statico, servizio OS | Discovery e raccolta evidenze sulla LAN autorizzata |
| 5 | Mobile | Flutter (Android/iOS), Riverpod, dio, go_router | Consultazione, scansione manuale via backend, push |
| 6 | Security Analysis Engine | modulo backend `analysis` | Regole → finding con severità/confidenza/evidenze |
| 7 | Device Fingerprinting Engine | modulo backend `fingerprinting` (+ hint agent) | Fusione evidenze, classificazione, confidenza per campo |
| 8 | Vulnerability Intelligence | modulo backend `vulnintel` | Mirror NVD/CPE + CISA KEV, matching versione |
| 9 | Notification System | modulo backend `alerts` | Alert con dedup, preferenze, canali (dashboard/email/push) |
| 10 | Reporting | modulo backend `reports` | PDF comprensibili per non tecnici |

## 4. Backend — monolite modulare

Un unico deployable Spring Boot con **moduli a confini espliciti** (package per dominio, API interne pubbliche, dettagli `internal`), verificati da test ArchUnit/Spring Modulith. I microservizi sono prematuri per l'MVP; i confini permettono di estrarli in futuro (es. `vulnintel`).

```
com.shsc
├── shared        (errori RFC 9457, paginazione, UUIDv7, clock, tenant context)
├── identity      (utenti, password Argon2id, JWT, refresh rotation, MFA TOTP)
├── tenancy       (tenant, organizzazioni, clienti, ruoli/permessi, RLS context)
├── homes         (abitazioni, reti, reti autorizzate)
├── agents        (enrollment, credenziali, heartbeat, eventi, revoca, update manifest)
├── scans         (richieste, state machine, dispatch job, ingestion risultati, ScanTrigger)
├── inventory     (dispositivi, osservazioni, porte, servizi, protocolli, override manuali)
├── fingerprinting(regole classificazione, OUI, confidenza per campo)
├── analysis      (Security Analysis Engine, finding, lifecycle)
├── vulnintel     (sync NVD/KEV, CPE matching)
├── risk          (Security Score spiegabile, snapshot, copertura)
├── alerts        (generazione, dedup, preferenze, delivery)
├── reports       (PDF)
├── billing       (piani, limiti, Stripe) 
├── integrations  (Home Assistant & co. — Milestone 15)
├── assistant     (AI provider-agnostic — Milestone 16)
├── admin         (super admin, operazioni piattaforma)
└── audit         (audit log append-only)
```

## 5. Agent Go — moduli

```
agent/go-security-agent/
├── cmd/shsc-agent/            main: run (servizio), enroll, status, diagnose, version
├── internal/core/             lifecycle, config, job runner, pipeline di scansione
├── internal/netif/            Network Interface Discovery (IP, mask, CIDR, gateway, tipo, IPv6)
├── internal/scope/            Guardia "rete autorizzata" (allow-list + RFC1918/ULA, limiti)
├── internal/discovery/arp/    ARP (Linux raw socket; Windows SendARP; macOS BPF/fallback)
├── internal/discovery/icmp/   Echo request controllato
├── internal/discovery/mdns/   DNS-SD browse
├── internal/discovery/ssdp/   M-SEARCH + device description (anti-SSRF)
├── internal/discovery/netbios/ NBSTAT
├── internal/discovery/rdns/   reverse DNS
├── internal/router/           UPnP IGD, TR-064, SNMP (solo credenziali fornite dal proprietario)
├── internal/dhcp/             lease via router integration
├── internal/fingerprint/      OUI lookup, hostname merge, hint di classificazione locali
├── internal/portscan/tcp/     TCP connect scanner (concorrenza, rate limit)
├── internal/portscan/udp/     probe UDP protocollo-specifiche
├── internal/service/          service & protocol detection (banner, HTTP, TLS, RTSP, SMB…)
├── internal/osfp/             OS fingerprinting (TTL, banner; TCP options solo in modalità privilegiata)
├── internal/analyzer/         controlli di sicurezza locali → evidenze
├── internal/collector/        Scan Result Collector (modello risultati versionato)
├── internal/store/            Local Storage (SQLite pure-Go: coda, stato, cache)
├── internal/cloud/            Cloud Connector (auth, long-poll job, upload, retry)
├── internal/health/           Health Monitor (heartbeat, metriche, autodiagnosi permessi)
├── internal/update/           Secure Update Manager (manifest firmato Ed25519, anti-rollback)
└── pkg/model/                 tipi condivisi del protocollo (JSON schema versionato)
```

Ogni modulo espone un'interfaccia piccola (`Discoverer`, `Prober`, `Analyzer`…) e restituisce risultati strutturati con `method`, `timestamp`, `evidence`. La pipeline orchestra i moduli in fasi; nessun file monolitico.

## 6. Frontend Angular — struttura

```
frontend/angular-dashboard/src/app/
├── core/        (auth, interceptors, tenant/home context, error handling, i18n)
├── shared/      (UI components: score gauge, severity badge, confidence chip…)
├── features/
│   ├── auth/ (login, registrazione, MFA)    ├── overview/       ├── homes/
│   ├── devices/ (lista, dettaglio)          ├── scans/ (manual scan, history)
│   ├── findings/  ├── vulnerabilities/      ├── network-map/    ├── reports/
│   ├── alerts/    ├── agents/               ├── integrations/   ├── subscription/
│   ├── settings/  └── organization/
```
Lazy loading per feature, guard per ruolo/permesso, client API generato da OpenAPI (openapi-generator, typescript-angular) per evitare drift.

## 7. Deployment

`docker-compose.yml`: `nginx` (TLS, reverse proxy, static frontend), `backend`, `postgres`, in dev anche `mailpit` (SMTP finto). Configurazione solo da environment variables / Docker secrets. In produzione: singola VPS economica sufficiente per l'MVP; TLS Let's Encrypt (certbot). Backup PostgreSQL giornaliero cifrato (pg_dump + retention) — vedi Milestone 2.

## 8. Predisposizione futura (non implementata nell'MVP)
- **Scan Scheduler**: vedi `02-MANUAL-SCAN-WORKFLOW.md §6`.
- **Raspberry Pi gateway**: l'agent è cross-compilabile `linux/arm64` e `linux/arm` senza CGO; nessuna modifica architetturale necessaria.
- **Monitoraggio continuo / scansione su nuovo dispositivo**: stessi `ScanTrigger` e stesso motore.
