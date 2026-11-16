# 11 — Roadmap dettagliata e checklist di sviluppo

Regola: una milestone alla volta, **approvazione esplicita** prima di passare alla successiva. Ogni milestone termina con: funzionalità, file creati/modificati, dipendenze, test e risultati, problemi, decisioni, prossima milestone.

| # | Milestone | Deliverable principali | Criterio di completamento |
|---|---|---|---|
| 1 | Analisi e architettura | documentazione `docs/`, ADR, stato progetto | approvazione architettura |
| 2 | Infrastructure & Docker | repo git dedicato, skeleton dei 4 progetti, `docker-compose.yml` (nginx TLS dev, postgres 18, backend, mailpit), `.env.example`, CI (build+test+lint+secret scan), Flyway baseline | `docker compose up` avvia stack sano; healthcheck verdi; CI verde |
| 3 | Backend auth & multi-tenancy | registrazione, login, JWT ES256, refresh rotation + reuse detection, MFA TOTP, RBAC, RLS, audit, rate limit, Problem Details, OpenAPI | test isolamento tenant e sicurezza auth verdi |
| 4 | Utenti, organizzazioni, homes | CRUD utenti/ruoli, organizzazioni, clienti, homes, reti; limiti piano (FREE) | API + test di autorizzazione per ogni ruolo |
| 5 | Agent core & enrollment | binario Go servizio (Win/Linux/macOS), enrollment token, chiavi Ed25519, token agent, heartbeat, revoca, coda SQLite, autodiagnosi capabilities | enrollment end-to-end, test revoca entro 30 s, test offline |
| 6 | Manual Scan Workflow | state machine, long-poll job firmati, progress/cancel, upload batch idempotenti, validazione scope, reaper; UI minima "Avvia scansione" + stato; discovery minima (interfacce + ARP) per un flusso reale | E2E: click → agent → risultati in dashboard; test cancel, agent offline, lease scaduto, upload tardivo |
| 7 | Network Discovery completa | ICMP, mDNS, SSDP/UPnP (anti-SSRF), NetBIOS, rDNS, UPnP IGD, TR-064, SNMP (credenziali proprietario), IPv6 NDP | test con responder MOCK; prova manuale su LAN reale autorizzata |
| 8 | Fingerprinting & classificazione | OUI sync IEEE, regole + punteggi, confidenza per campo, MAC randomizzati, classificazione manuale + storico, OS fingerprint base | test regole (positivi e negativi "indizio debole") |
| 9 | Port scanning & service detection | TCP connect con rate limit, UDP probe, banner/HTTP/TLS/RTSP OPTIONS/SMB negotiate/ONVIF/IPP | test con servizi MOCK; nessuna probe vietata (test di policy) |
| 10 | Security analysis & vuln intel | regole finding, lifecycle/dedup, sync NVD/CPE/KEV/EPSS, matching conservativo | test falsi positivi (no match solo produttore) |
| 11 | Risk engine | score spiegabile, copertura, snapshot, delta | test casi limite (copertura bassa, dispositivo sconosciuto) |
| 12 | Dashboard Angular completa | tutte le 19 pagine, IT/EN, responsive, network map | test unit + E2E Playwright |
| 13 | Alerts & PDF reports | alert con dedup/preferenze, email SMTP, report PDF IT/EN | test dedup, snapshot PDF |
| 14 | Flutter app | login, dashboard, devices, scansione manuale, push FCM | test widget + integration |
| 15 | Integrazioni | Home Assistant (API ufficiale, token long-lived dal proprietario), valutazione Matter | test con HA in container |
| 16 | AI Security Assistant | porta `AssistantProvider` multi-provider, risposte solo da dati del tenant, nessuna azione | test di grounding / no-hallucination su fixture |
| 17 | SaaS, Stripe, white label | piani, trial, checkout, portal, webhook firmati, limiti, branding B2B | test webhook idempotenti (Stripe test mode) |
| 18 | Hardening, test, release | pen-test interno, threat model rivisto, firma codice agent, backup/restore, monitoring, documentazione utente | checklist release completata |
| F | Scan Scheduler & monitoraggio continuo | **non implementata nell'MVP** — solo predisposizione | — |

## Checklist trasversale (Definition of Done di ogni feature)
- [ ] Codice modulare, nessun metodo vuoto o stub, nessuna funzionalità finta
- [ ] Test unitari + integrazione (Testcontainers per DB) + test di autorizzazione/tenant
- [ ] Validazione input, errori RFC 9457, log senza segreti
- [ ] Permessi RBAC e scope verificati; audit dove previsto
- [ ] Testi IT/EN
- [ ] Migrazione Flyway (se schema)
- [ ] OpenAPI aggiornata
- [ ] Dipendenze nuove spiegate in `TECHNICAL_DECISIONS.md` (licenza, costo, alternative)
- [ ] `PROJECT_STATUS.md` aggiornato
- [ ] Dati MOCK marcati `is_mock`/`[MOCK]` e rifiutati dal profilo `prod`
- [ ] Nessuna scansione automatica, nessun target fuori dalle reti autorizzate

## Strategia di test e dispositivi MOCK
- **Backend**: JUnit 5, Spring Boot Test, Testcontainers PostgreSQL, MockMvc/REST Assured, ArchUnit (confini moduli, accesso dati tenant).
- **Frontend**: test unitari (runner di default della versione Angular scelta), Playwright E2E.
- **Agent**: `go test`, fake di rete in-process (listener TCP su loopback con banner, responder SSDP/mDNS su interfacce di test), test di policy che verificano l'assenza di probe vietate e il rifiuto di target fuori scope.
- **E2E di scansione**: rete Docker dedicata con container "dispositivi MOCK" (RTSP finto, IPP finto, broker MQTT, web admin HTTP, responder SSDP) etichettati `MOCK`; l'agent in container scansiona solo quella rete. Il backend in profilo `prod` rifiuta risultati con flag mock.
- Suite obbligatorie: tenant isolation, manual scan workflow, agent offline, revoca credenziali, security (authn/authz, injection, XSS da dati dispositivo).
