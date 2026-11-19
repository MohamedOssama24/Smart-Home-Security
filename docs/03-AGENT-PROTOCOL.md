# 03 — Comunicazione Agent ↔ Backend

> **Stato (Milestone 6)**: job firmati Ed25519 con long polling, ack, progress con lease, annullamento, risultati a lotti idempotenti e chiusura (§6-§8) sono **implementati**; contratto in [15-MANUAL-SCANS.md](15-MANUAL-SCANS.md).

> **Stato (Milestone 7)**: le osservazioni hanno anche `hostname` e `details`; metodi ARP, SELF, ICMP, MDNS, SSDP, UPNP_IGD, NETBIOS, RDNS, NDP, TR064, SNMP; `capabilities.routerIntegrations` riporta solo i nomi delle integrazioni router. Vedi [16-NETWORK-DISCOVERY.md](16-NETWORK-DISCOVERY.md).

> **Stato (Milestone 5)**: enrollment, autenticazione, revoca, rotazione (M3), heartbeat, eventi con coda SQLite locale, autodiagnosi delle capabilities ed esecuzione come servizio sono **implementati**. Contratto esatto in [14-AGENT-RUNTIME.md](14-AGENT-RUNTIME.md). Rispetto al progetto qui sotto:
> - heartbeat ogni **25 s** (non 60 s), deciso dal server: la credenziale è ricontrollata nel DB a ogni richiesta, senza cache, quindi l'agent scopre la revoca entro 25 s e si ferma (§4–5);
> - gli eventi dell'agent hanno un endpoint dedicato `POST /agent/events`, idempotente;
> - servizi realizzati con `golang.org/x/sys` invece di `kardianos/service` (§10);
> - macOS: chiave in file `0600` di root, non nel Keychain di sistema (§2.3);
> - le interfacce sono salvate e mostrate, ma non diventano ancora reti candidate (§2.6); job, risultati e aggiornamenti firmati (§6–9) arrivano nelle milestone successive.

## 1. Principi
- **Solo connessioni in uscita** dall'agent verso `https://<api>/api/v1/agent/**` (TLS 1.2+, preferibilmente 1.3, verifica certificato obbligatoria, nessun `InsecureSkipVerify`).
- **Identità dell'agent = coppia di chiavi Ed25519 generata localmente.** La chiave privata non lascia mai la macchina.
- Messaggi JSON con `schemaVersion`; il backend accetta N e N-1.
- Tutte le operazioni di scrittura sono **idempotenti** (chiavi `scanId` + `batchSeq`).

## 2. Enrollment (token monouso a scadenza)

1. L'utente (permesso `agent:enroll`) genera dalla dashboard un **enrollment token** per una home: 32 byte casuali, mostrato una sola volta, salvato come SHA-256, **monouso**, scadenza 30 min, revocabile.
2. Installazione: `shsc-agent enroll --token <TOKEN> --api https://...`
3. L'agent genera la coppia Ed25519, salva la privata in archivio protetto (Windows: DPAPI machine scope; macOS: Keychain System; Linux: file `0600` di proprietà dell'utente di servizio).
4. `POST /agent/enroll {token, publicKey, hostInfo{os, arch, hostname, agentVersion}, interfaces[]}`
5. Il backend, in un'unica transazione: verifica hash+scadenza+non usato, marca il token usato, crea `agents` (`agentId` UUID) e `agent_credentials` (chiave pubblica, `status=ACTIVE`), registra audit. Risponde `{agentId, homeId, config}`.
6. Le interfacce riportate diventano **reti candidate**: l'utente deve confermarle come autorizzate dalla dashboard (dichiarando di esserne proprietario/autorizzato). Senza rete autorizzata non si può scansionare.

## 3. Autenticazione delle richieste
Schema tipo *private_key_jwt* (RFC 7523):
1. L'agent firma un'asserzione JWT (EdDSA) `{iss: agentId, aud: <api>/agent/token, iat, exp ≤ 60s, jti random}`.
2. `POST /agent/token` → il backend verifica firma con la chiave pubblica registrata, `jti` non riusato (anti-replay, tabella con TTL), credenziale `ACTIVE` → rilascia un **access token agent** (JWT, 10 min, `scope=agent`, `agentId`, `tenantId`, `homeId`).
3. Ogni chiamata agent usa `Authorization: Bearer <token>`; lo stato della credenziale viene ricontrollato a ogni richiesta (cache ≤ 30 s) → **la revoca ha effetto entro 30 s**.

Perché non mTLS nell'MVP: richiede una CA privata e configurazione Nginx più complessa; l'approccio a firma offre le stesse garanzie di possesso della chiave. mTLS resta un'opzione di hardening (ADR-007).

## 4. Revoca e rotazione
- Revoca da dashboard o automatica (es. agent dichiarato compromesso): `agent_credentials.status=REVOKED`, scansioni attive → FAILED (`AGENT_REVOKED`), audit + alert.
- L'agent revocato riceve `401 {code: AGENT_REVOKED}`: smette di operare, cancella la coda locale non inviata e richiede un nuovo enrollment.
- Rotazione chiave: `POST /agent/credentials/rotate` firmato con la chiave corrente, nuova chiave pubblica; la vecchia resta valida 5 min.

## 5. Heartbeat
`POST /agent/heartbeat` ogni 60 s: `{agentVersion, uptime, interfaces (hash + dettaglio se cambiato), capabilities{arp: raw|os_api|unavailable, icmp, privileged}, queueDepth, lastError}`. Risposta: `{serverTime, configVersion, updateAvailable?}`.
Stato agent: `ONLINE` (< 3 min), `STALE` (3–15 min), `OFFLINE` (> 15 min → alert "Agent offline", con dedup).

## 6. Ricezione dei job — long polling
`GET /agent/jobs/next?wait=30` → `200 {job}` oppure `204` dopo 30 s. Implementazione Spring `DeferredResult` + notifica in-process quando una scansione viene accodata. Funziona attraverso proxy e firewall aziendali. WebSocket valutabile in futuro.

Il job contiene `{scanId, profile, targets, authorizedCidrs, limits{maxHosts, rate, concurrency}, issuedAt, expiresAt}` ed è **firmato dal backend** (Ed25519, chiave pubblica distribuita all'enrollment): anche con un MITM sul TLS l'agent non esegue job non firmati.

## 7. Avanzamento, annullamento, risultati
- `POST /agent/scans/{id}/ack` → RUNNING, lease.
- `POST /agent/scans/{id}/progress` ogni ≤ 5 s → risposta `{cancelRequested: bool}`.
- `POST /agent/scans/{id}/results` a batch (≤ 500 osservazioni o ≤ 2 MB, gzip) con `batchSeq`; ri-invio dello stesso `batchSeq` = no-op. Campo opzionale `homeAssistant` (M15) in un batch dedicato senza porte, uno per scansione: vedi [24-INTEGRATIONS.md](24-INTEGRATIONS.md) §3.
- `POST /agent/scans/{id}/complete {totalBatches, summary, warnings[], errors[], cancelled: bool}`.
- Il backend valida: JSON schema, dimensioni, che **ogni IP osservato appartenga ai CIDR autorizzati del job** (altrimenti scarto + audit + warning), coerenza `agentId ↔ scan`.

## 8. Coda locale e sincronizzazione
- Ogni batch viene scritto nello store SQLite locale **prima** dell'invio; eliminato solo dopo `2xx`.
- Disconnessione: la scansione prosegue; upload con backoff esponenziale + jitter (1 s → 5 min).
- Se il lease scade nel frattempo la scansione diventa FAILED (`AGENT_LOST`), ma i risultati inviati in ritardo entro 24 h vengono accettati come **risultati tardivi** e la scansione passa a `COMPLETED_WITH_WARNINGS` (warning `LATE_UPLOAD`). Oltre 24 h vengono scartati.
- Limite coda: 200 MB, poi scarto dei più vecchi con evento registrato.

## 9. Aggiornamenti firmati
- Manifest `{version, os, arch, url, sha256, minVersion, releasedAt}` firmato Ed25519 con chiave di **release offline** (diversa da quella dei job). La chiave pubblica è incorporata nel binario.
- L'agent verifica firma, hash, **anti-rollback** (versione > corrente), scarica, sostituisce atomicamente, riavvia il servizio; rollback automatico se il nuovo binario non invia heartbeat entro 2 min.
- Nell'MVP l'aggiornamento è proposto e applicato su conferma dell'utente; evoluzione verso TUF (`go-tuf`) documentata in ADR-008.

## 10. Esecuzione come servizio e privilegi
| OS | Servizio | Privilegi |
|---|---|---|
| Windows | Windows Service (`kardianos/service`) | `LocalService`; ARP via `SendARP`/`GetIpNetTable2`, ICMP via `IcmpSendEcho` (iphlpapi) → **nessun Npcap richiesto** |
| Linux | systemd, utente dedicato `shsc` | `AmbientCapabilities=CAP_NET_RAW` (ARP/ICMP raw), nient'altro |
| macOS | launchd daemon | root per BPF (ARP raw); fallback senza privilegi = lettura tabella ARP dopo sweep TCP |

L'agent riporta nelle `capabilities` cosa può fare: se una tecnica non è disponibile, la copertura cala e compare un warning esplicito (mai un fallimento silenzioso).
