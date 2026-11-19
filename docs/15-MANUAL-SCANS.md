# 15 — Scansioni manuali (Milestone 6)

Questo documento descrive ciò che è **implementato** nella Milestone 6. Il disegno complessivo è in [02-MANUAL-SCAN-WORKFLOW.md](02-MANUAL-SCAN-WORKFLOW.md) e [03-AGENT-PROTOCOL.md](03-AGENT-PROTOCOL.md) §6-§8. Decisioni: ADR-037…ADR-041.

Una scansione parte **solo** da un'azione esplicita dell'utente (`trigger = MANUAL`, vincolo `CHECK` nel database). Nessuna scansione è pianificata. Il solo profilo disponibile è `DISCOVERY`, cioè interfacce e ARP: nessuna porta contattata, nessuna credenziale provata, nessun pacchetto verso reti non autorizzate o non collegate direttamente all'agent. Gli host trovati sono **indirizzi in uso**, non vulnerabilità.

> **M9**: sono disponibili anche `QUICK` e `STANDARD`, che dopo la discovery controllano porte e servizi in sola lettura (fase `PORTS`, limiti `limits.ports` nel job firmato). Vedi [18-PORT-SCANNING.md](18-PORT-SCANNING.md).

## 1. Macchina a stati
`PENDING → QUEUED → RUNNING → COMPLETED | COMPLETED_WITH_WARNINGS | FAILED | CANCELLED`; da `QUEUED` anche `CANCELLED` / `FAILED`. Unica transizione da uno stato finale: `FAILED → COMPLETED_WITH_WARNINGS` per i risultati arrivati in ritardo (`LATE_UPLOAD`).

- Ogni transizione usa il lock ottimistico (`version`) ed è registrata in `scan_events` (attore USER / AGENT / SYSTEM, motivo).
- Al massimo **una scansione attiva per abitazione** (indice unico parziale).
- Motivi di fallimento: `AGENT_OFFLINE` (job non ritirato entro 10 min), `AGENT_LOST` (lease scaduto), `TIMEOUT` (oltre 15 min), `AGENT_REVOKED`, `AGENT_ABORTED`; annullamento dell'utente: `USER_CANCELLED`.

## 2. Creazione (`POST /api/v1/homes/{id}/scans`)
Controlli, in quest'ordine, sotto lock dell'abitazione:

1. permesso `scan:create` sull'abitazione;
2. `Idempotency-Key` (8-64 caratteri) già usata dallo stesso utente → 200 con la stessa scansione;
3. profilo `DISCOVERY`;
4. almeno una rete autorizzata (`NO_AUTHORIZED_NETWORK`);
5. un agent ONLINE (`AGENT_OFFLINE`);
6. nessuna scansione attiva (`SCAN_ALREADY_ACTIVE`);
7. limite del piano: FREE 10 scansioni per abitazione nelle ultime 24 h (`PLAN_LIMIT_REACHED`).

Gli obiettivi (`scan_targets`) sono le reti autorizzate **al momento della richiesta**. La richiesta è registrata in audit (`SCAN_REQUESTED`).

## 3. Job firmati e long polling
- L'agent chiede `GET /api/v1/agent/jobs/next?wait=≤25` (thread virtuali). Il backend lo sveglia dopo il commit della richiesta e ricontrolla il database ogni 5 s. Risposta 204 se non ci sono job.
- Il job è un JSON firmato **Ed25519** dal backend (`SHSC_JOB_SIGNING_KEY`, generata con `infrastructure/scripts/generate-job-signing-key.sh`). Contiene scansione, agent, abitazione, profilo, obiettivi, limiti (`maxHosts` 1024, 50 richieste/s, concorrenza 16, durata massima) e scadenza.
- La chiave pubblica è inviata all'enrollment e salvata in `agent.json`. Gli agent registrati prima della M6 la ricevono una volta dalla sessione, su TLS verificato.
- L'agent rifiuta job con firma non valida, scaduti, per un altro agent, con profilo sconosciuto, con reti non private o con limiti fuori dai valori ammessi.

## 4. Esecuzione, avanzamento, annullamento
- `ack` porta la scansione in `RUNNING` con lease di 2 min. Ogni `progress` (fase, percentuale, dispositivi trovati) rinnova il lease e risponde se l'utente ha chiesto l'annullamento.
- **Annullamento**: in `QUEUED` è immediato. In `RUNNING` è una richiesta che l'agent riceve al progress successivo; l'agent interrompe la discovery e chiude con `CANCELLED`.
- **Reaper** (ogni 30 s, funzione `scans_due_for_reaping` SECURITY DEFINER): applica la scadenza della coda, il lease e la durata massima.
- La revoca di un agent fa fallire le sue scansioni attive.

## 5. Risultati
- Lotti numerati di al massimo 500 osservazioni (`POST /agent/scans/{id}/results`), idempotenti su `(scan_id, batch_seq)`.
- Ogni IP è confrontato con gli obiettivi della scansione: quelli fuori ambito sono scartati, contati, registrati in audit (`SCAN_RESULTS_OUT_OF_SCOPE`) e segnalati con l'avviso `OUT_OF_SCOPE_RESULTS`.
- `complete` verifica che siano arrivati tutti i lotti (`MISSING_BATCHES` altrimenti) ed è idempotente.
- Dopo un `AGENT_LOST`, i risultati sono accettati per 24 h e la scansione diventa `COMPLETED_WITH_WARNINGS` con `LATE_UPLOAD`; oltre le 24 h sono rifiutati.
- Sull'agent, lotti e chiusura passano dalla coda SQLite (tipo `scan`): nulla si perde se il backend non è raggiungibile.

## 6. Discovery minima (agent)
- Solo gli obiettivi IPv4 contenuti in una sottorete **collegata direttamente** a un'interfaccia; gli altri producono `TARGET_NOT_CONNECTED`, IPv6 `IPV6_NOT_SUPPORTED`. Il limite `maxHosts` produce `HOST_LIMIT_REACHED`.
- **Windows**: `SendARP` (IP Helper), senza privilegi né Npcap.
- **Linux**: richieste ARP raw (`AF_PACKET`, richiede `CAP_NET_RAW`, già concessa dall'unità systemd). Senza la capability legge solo `/proc/net/arp` (`ARP_TABLE_ONLY`).
- **macOS e altri sistemi**: `ARP_UNAVAILABLE` (rimandato).
- Il computer dell'agent compare come osservazione `SELF` se il suo indirizzo è nell'obiettivo.

## 7. API utente
| Metodo | Percorso | Permesso |
|---|---|---|
| POST | `/api/v1/homes/{homeId}/scans` (`{"profile":"DISCOVERY"}`, header `Idempotency-Key`) | `scan:create` |
| GET | `/api/v1/homes/{homeId}/scans` (ultime 20) | `scan:read` |
| GET | `/api/v1/scans/{id}` (con obiettivi ed eventi) | `scan:read` |
| POST | `/api/v1/scans/{id}/cancel` | `scan:create` |
| GET | `/api/v1/scans/{id}/devices` (un elemento per IP) | `scan:read` |

Ruoli: admin, tecnico e cliente hanno `scan:create` e `scan:read`; il ruolo in sola lettura ha `scan:read`.

## 8. Dashboard
Pagina **Scansioni** dell'abitazione (`/homes/{id}/scans`):

- pulsante "Avvia scansione", con la stessa chiave di idempotenza se si riprova dopo un errore;
- stato con percentuale e aggiornamento ogni 3 s, pulsante di annullamento, storico;
- per la scansione terminata: avvisi tradotti e dispositivi trovati (IP, MAC, metodo), con la nota che non si tratta di vulnerabilità.

Testi in italiano e inglese.
