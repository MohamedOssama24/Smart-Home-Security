# 14 — Agent: servizio, heartbeat, coda locale, autodiagnosi (Milestone 5)

Questo documento descrive ciò che è **implementato** nella Milestone 5. L'identità dell'agent (enrollment, asserzioni firmate, rotazione) è in [12-AUTHENTICATION.md](12-AUTHENTICATION.md); il protocollo completo, comprese le parti future (job, risultati, aggiornamenti), è in [03-AGENT-PROTOCOL.md](03-AGENT-PROTOCOL.md). Decisioni: ADR-031…ADR-036.

L'agent **non avvia scansioni e non invia pacchetti di rete**: in questa milestone si autentica, segnala che è vivo, descrive cosa saprebbe fare e consegna i propri eventi. Le scansioni (manuali) arrivano con la Milestone 6.

## 1. Comandi
| Comando | Cosa fa |
|---|---|
| `shsc-agent enroll --api URL --token-file F [--ca-file F] [--name N]` | genera la coppia Ed25519 e registra l'agent con il token monouso. La CA indicata viene **copiata** in `<state>/ca.pem` con percorso assoluto, così il servizio funziona da qualunque cartella e con un altro account |
| `shsc-agent run [--state-dir D] [--log-file F]` | ciclo dell'agent (usato dal servizio): heartbeat, autodiagnosi, consegna degli eventi |
| `shsc-agent service install\|uninstall\|start\|stop\|status` | gestione del servizio di sistema (install/uninstall/start/stop richiedono amministratore/root; `status` no) |
| `shsc-agent diagnose [--json] [--offline]` | capabilities, interfacce, stato della coda locale e raggiungibilità del backend |
| `shsc-agent status` · `rotate-key` · `version` | invariati dalla Milestone 3 |

Codici di uscita: `0` ok · `1` errore · `2` uso errato · `3` **agent revocato** · `4` agent non registrato. I gestori di servizio sono configurati per **non** riavviare con 3 e 4.

Cartella di stato (predefinita): Windows `%ProgramData%\SHSC\agent`, Linux `/var/lib/shsc-agent`, macOS `/Library/Application Support/SHSC/agent`. Contiene `agent.json`, `agent.key`, `ca.pem` (facoltativo), `queue.db`, `agent.log` (solo Windows servizio, rotazione a 5 MB).

## 2. Servizio di sistema
Implementato con `golang.org/x/sys` (nessuna libreria di servizio di terze parti, ADR-032).

| OS | Configurazione |
|---|---|
| Windows | servizio `shsc-agent`, account **LocalService**, avvio automatico ritardato, ripristino: riavvio dopo 10 s / 30 s / 1 min (azzeramento 24 h), anche per uscite con errore non dovute a crash. Un agent revocato termina in modo pulito e non viene riavviato |
| Linux | unità systemd, utente dedicato `shsc`, solo `CAP_NET_RAW` (ambient), `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `ReadWritePaths` = cartella di stato, `Restart=on-failure`, `RestartPreventExitStatus=3 4` |
| macOS | daemon launchd, `KeepAlive` condizionato all'esistenza di `agent.json` (dopo la revoca il file viene archiviato, quindi launchd non lo riavvia) |

`service install` rifiuta eseguibili in cartelle scrivibili da utenti non privilegiati (Linux/macOS: proprietario root, non scrivibile da gruppo/altri, non sotto `/home`, `/root`, `/Users`) e percorsi con caratteri che altererebbero il file di unità.

## 3. Protezione delle chiavi
- Linux/macOS: cartella `0700`, file `0600`, scrittura atomica.
- Windows: chiave privata cifrata con **DPAPI machine scope** + entropia applicativa (prefisso `SHSC-DPAPI-1`); la cartella riceve una ACL protetta (nessuna ereditarietà) con accesso solo a SYSTEM, Administrators, LocalService e all'utente che ha eseguito l'enrollment. Chiavi PEM in chiaro di versioni precedenti restano leggibili e vengono cifrate alla successiva rotazione (ADR-034).
- `rotate-key` conserva il proprietario dei file (comando eseguito da root per un servizio con utente `shsc`).

## 4. Heartbeat
`POST /api/v1/agent/heartbeat` (token agent) **ogni 25 s**, intervallo deciso dal server (`shsc.agent.heartbeat-interval`, risposta `heartbeatIntervalSeconds`). L'agent anticipa a caso fino al 10 % per distribuire il carico, mai ritarda (ADR-033).

Richiesta:
```json
{ "schemaVersion": 1, "agentVersion": "1.0.0", "uptimeSeconds": 120,
  "interfacesHash": "<sha256 esadecimale>", "interfaces": [ {"name": "eth0", "mac": "aa:bb:…", "mtu": 1500, "addresses": ["192.168.1.10/24"]} ],
  "capabilities": {"privileged": false, "arp": "os_api", "icmp": "os_api", "warnings": []},
  "queueDepth": 0, "lastError": "…" }
```
- `interfaces` è inviato solo quando l'hash cambia (o al primo heartbeat); massimo 32 interfacce, 16 indirizzi ciascuna.
- `arp`: `raw` · `os_api` · `os_table` · `unavailable`; `icmp`: `raw` · `unprivileged` · `os_api` · `unavailable`.
- `lastError`: ultimo errore di comunicazione (≤ 300 caratteri), inviato al primo heartbeat riuscito dopo un'interruzione e poi azzerato.
- Risposta `200 {serverTime, heartbeatIntervalSeconds}`; `401 AGENT_REVOKED` se revocato.

**Connettività** (calcolata alla lettura da `last_heartbeat_at`): `ONLINE` < 3 min · `STALE` < 15 min · `OFFLINE` · `NEVER_CONNECTED` · `REVOKED`.

**Revoca**: ogni richiesta agent ricontrolla la credenziale nel DB, quindi l'agent scopre la revoca al primo heartbeat successivo (≤ 25 s). A quel punto svuota la coda locale, cancella le chiavi, rinomina `agent.json` in `agent.revoked-<data>.json` ed esce con codice 3. Per riutilizzare la macchina serve un nuovo enrollment.

## 5. Eventi e coda locale
Gli eventi vengono scritti **prima** in una coda SQLite locale (`queue.db`, `modernc.org/sqlite`, ADR-031) e cancellati solo dopo la conferma del backend.

| Evento | Quando | `detail` |
|---|---|---|
| `AGENT_STARTED` | avvio | `agentVersion`, `os`, `arch` |
| `AGENT_STOPPED` | arresto pulito | `uptimeSeconds` |
| `CAPABILITIES_CHANGED` | autodiagnosi diversa dalla precedente (verifica ogni 10 min) | `previous`, `current` |
| `CONNECTION_RESTORED` | backend di nuovo raggiungibile | `offlineSeconds`, `failedAttempts` |
| `QUEUE_OVERFLOW` | coda oltre 200 MB: eliminati i più vecchi | `dropped` |

`POST /api/v1/agent/events {schemaVersion, events: [{id, type, occurredAt, detail}]}` (1–100 per richiesta) → `200 {accepted, duplicates}`. L'`id` è scelto dall'agent: un reinvio è un duplicato innocuo (`UNIQUE(agent_id, event_id)`). `detail` ≤ 4 KB; date nel futuro oltre 5 min vengono sostituite con l'ora del server. Se un lotto viene rifiutato con `400`, l'agent reinvia gli eventi uno alla volta e scarta solo quelli non validi. Il backend conserva gli **ultimi 500 eventi** per agent (ADR-036).

**Disconnessione**: backoff esponenziale con jitter da 1 s a 5 min; gli eventi restano in coda anche dopo un riavvio.

## 6. Autodiagnosi delle capabilities
Apre e chiude soltanto socket/handle per verificare cosa è permesso: **nessun pacchetto viene inviato**.

| OS | ARP | ICMP |
|---|---|---|
| Linux | `raw` con `CAP_NET_RAW` (socket `AF_PACKET`), altrimenti `os_table` (`/proc/net/arp`) | `raw`, oppure `unprivileged` (`ping_group_range`) |
| macOS | `raw` se `/dev/bpf*` è apribile, altrimenti `os_table` | `unprivileged` (socket ICMP datagram) |
| Windows | `os_api` (`GetIpNetTable2`, iphlpapi) — nessun Npcap | `os_api` (`IcmpCreateFile`) |

Avvisi: `ARP_TABLE_ONLY`, `ARP_UNAVAILABLE`, `ICMP_UNAVAILABLE`, `NO_USABLE_INTERFACE`. Una tecnica mancante riduce la copertura con un avviso esplicito, mai in silenzio.

## 7. API utente
- `GET /homes/{homeId}/agents`, `GET /agents/{id}`: in più `connectivity`, `lastHeartbeatAt`, `capabilities`, `interfaces`, `queueDepth`, `uptimeSeconds`, `lastError`.
- `GET /agents/{id}/events` (permesso `agent:read`): ultimi 50 eventi, più recenti prima.
- Limite del piano: **2 agent attivi per abitazione** nel piano FREE (`plans.max_agents_per_home`). Verificato alla creazione del token e di nuovo all'enrollment sotto lock del tenant → `409 PLAN_LIMIT_REACHED`. Gli agent revocati non contano (ADR-035).

## 8. Dashboard
Nel dettaglio abitazione ogni agent mostra lo stato di connettività e l'ultimo heartbeat; "Diagnostica" apre capabilities, avvisi, interfacce, ultimo errore ed eventi recenti. Dopo l'enrollment la pagina suggerisce il comando `service install`. Pagina Organizzazione: riga "Agent per abitazione" nel piano.

## 9. Test
- Agent: coda (idempotenza, limite e overflow, persistenza), capabilities, runner contro un backend di test TLS (heartbeat, revoca entro l'intervallo, offline e ripresa, persistenza al riavvio, evento non valido scartato, backoff), servizi (template systemd/launchd e validazione percorsi), DPAPI e ACL (eseguiti su Windows), CLI.
- Backend: `AgentRuntimeTest` (heartbeat e diagnosi, ONLINE/STALE/OFFLINE, revoca → `AGENT_REVOKED`, eventi idempotenti e visibili solo nel tenant, validazione, limite agent per abitazione, conservazione degli ultimi 500 eventi).
- Frontend: badge di connettività e pannello diagnostica.
- End-to-end sullo stack di sviluppo con il binario Windows reale: enrollment, `diagnose`, `run`, backend fermato per 154 s e ripresa automatica (`CONNECTION_RESTORED`), revoca da API → agent fermo con codice 3 dopo **10 s**, chiavi cancellate.
