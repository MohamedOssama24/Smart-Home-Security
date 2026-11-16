# 02 — Flusso della scansione manuale

> Requisito fondamentale MVP: **ogni scansione è avviata manualmente da un utente.** Nessun job periodico di scansione esiste nell'MVP.

## 1. Sequenza

```
Utente      Dashboard/App        Backend (scans)                 Agent                    LAN
  │ "Avvia scansione"│                  │                           │                        │
  ├─────────────────►│ POST /homes/{h}/scans (Idempotency-Key)      │                        │
  │                  ├─────────────────►│ 1 valida: permesso scan:create, piano,           │
  │                  │                  │   agent ONLINE, nessuna scansione attiva,        │
  │                  │                  │   target ⊆ reti autorizzate                       │
  │                  │                  │ 2 crea scan PENDING → QUEUED (job firmato)        │
  │                  │◄── 202 {scanId, status:QUEUED}                │                        │
  │                  │                  │◄── long-poll GET /agent/jobs/next ────┤           │
  │                  │                  ├── job {scanId, profile, targets} ────►│           │
  │                  │                  │◄── POST /agent/scans/{id}/ack ────────┤ RUNNING   │
  │                  │                  │                           │ verifica scope locale  │
  │                  │                  │                           ├── discovery ──────────►│
  │                  │                  │◄── POST progress {fase, %, n} ────────┤ (ogni ≤5s)│
  │                  │ GET /scans/{id} (polling 2s)                 │◄── risposte ───────────┤
  │                  │                  │ risposta progress: cancelRequested?   │           │
  │                  │                  │◄── POST results batch 1..N (idempotenti) ─┤       │
  │                  │                  │◄── POST complete {summary, warnings} ─┤           │
  │                  │                  │ 3 valida schema+scope, salva osservazioni,       │
  │                  │                  │   fingerprinting → analysis → vulnintel → risk  │
  │                  │                  │ 4 COMPLETED / COMPLETED_WITH_WARNINGS / FAILED  │
  │                  │◄── stato finale + risultati                  │                        │
```

L'agent si connette **sempre in uscita** (HTTPS). Non serve aprire porte né port-forwarding nella casa dell'utente; funziona dietro NAT e CGNAT.

## 2. Macchina a stati

```
 PENDING ──valida──► QUEUED ──ack agent──► RUNNING ──► COMPLETED
    │                  │                     │    └──► COMPLETED_WITH_WARNINGS
    │                  │                     └───────► FAILED
    └──► FAILED        ├──► CANCELLED        └───────► CANCELLED
         (validazione) └──► FAILED (job non ritirato entro TTL)
```

| Transizione | Chi | Condizione |
|---|---|---|
| PENDING → QUEUED | backend | validazioni superate (nella stessa transazione della creazione) |
| PENDING → FAILED | backend | validazione fallita (motivo in `failure_reason`) |
| QUEUED → RUNNING | agent (ack) | agent assegnato ritira il job; acquisisce un **lease** (es. 120 s, rinnovato da ogni progress) |
| QUEUED → CANCELLED | utente | annullamento prima del ritiro: immediato |
| QUEUED → FAILED | backend (reaper) | job non ritirato entro `queue_ttl` (es. 10 min): agent offline |
| RUNNING → CANCELLED | agent | l'utente ha impostato `cancel_requested_at`; l'agent lo riceve nella risposta al progress, interrompe, carica i risultati parziali e conferma |
| RUNNING → COMPLETED | backend | risultati completi, nessun warning |
| RUNNING → COMPLETED_WITH_WARNINGS | backend | completata ma con copertura ridotta (es. ARP non disponibile per permessi, host non analizzabili, timeout parziali) |
| RUNNING → FAILED | backend | errore agent, risultati non validi, lease scaduto (agent perso) o `max_duration` superata |

Stati terminali: COMPLETED, COMPLETED_WITH_WARNINGS, FAILED, CANCELLED. Ogni transizione è registrata (`scan_events`) con timestamp e attore; transizioni non ammesse → `409 Conflict`. Le transizioni usano **optimistic locking** (`version`) per evitare race tra cancel e complete.

L'annullamento è "best effort" (come richiesto: *quando tecnicamente possibile*): il pulsante mostra "Annullamento in corso…" finché l'agent non conferma; se il lease scade la scansione passa a FAILED con motivo `AGENT_LOST`.

## 3. Regole di validazione alla creazione
1. Permesso `scan:create` sulla home (RBAC + scope cliente/home).
2. Home del tenant corrente (tenant isolation).
3. Almeno un agent della home in stato `ACTIVE` con heartbeat < 3 min.
4. **Al massimo una scansione non terminale per home** (vincolo DB: indice unico parziale).
5. Limiti piano (scansioni/giorno, profili consentiti, numero dispositivi).
6. Target: `ALL_AUTHORIZED` oppure lista di dispositivi/IP **tutti contenuti in reti autorizzate** della home.
7. `Idempotency-Key` per evitare doppie scansioni da doppio click.
8. Rate limit per utente e per home.

## 4. Dati mostrati dalla dashboard
`status`, `requestedAt`, `startedAt`, `completedAt`, `progress` (fase corrente + %), `devicesDiscovered`, `devicesAnalyzed`, `devicesNotAnalyzable` (con motivo), `warnings[]`, `errors[]`, `missingInformation[]` (es. "Integrazione router non configurata: hostname DHCP non disponibili"), `coverage`, link ai risultati.

Fasi di progresso: `PREPARING → INTERFACES → DISCOVERY → PORT_SCAN → SERVICE_DETECTION → LOCAL_ANALYSIS → UPLOADING`, poi lato backend `ANALYZING`.

## 5. Profili di scansione (selezionabili dall'utente)

| Profilo | Contenuto | Durata indicativa (/24) |
|---|---|---|
| `DISCOVERY` | solo individuazione dispositivi e identificazione | 1–2 min |
| `QUICK` | discovery + ~40 porte TCP comuni IoT/admin + UDP essenziali | 3–5 min |
| `STANDARD` | discovery + ~300 porte TCP + service detection completa | 8–15 min |
| `DEEP` (piani superiori) | TCP 1–1024 + porte IoT note >1024 + OS fingerprinting | 20–40 min |

Selezione target: tutta la rete autorizzata, oppure singoli dispositivi già noti (scansione mirata).

## 6. Predisposizione per lo Scan Scheduler futuro (NON attivo)

Lo **stesso** motore serve manuale e automatico. La scansione ha un campo `trigger`:

```java
enum ScanTrigger { MANUAL /* MVP */, SCHEDULED, NEW_DEVICE_EVENT, CONTINUOUS }
```

- Il punto d'ingresso unico è `ScanRequestService.request(ScanRequestCommand cmd)`; il controller REST lo invoca con `trigger=MANUAL` e `requestedBy=<userId>`.
- Un futuro modulo `scheduler` invocherà lo stesso metodo con `trigger=SCHEDULED` e `requestedBy=null`.
- Nell'MVP: il vincolo DB `CHECK (trigger = 'MANUAL')` impedisce fisicamente scansioni non manuali; verrà rimosso con una migrazione quando la milestone futura sarà approvata. **Nessuna classe scheduler, nessun `@Scheduled` per scansioni, nessun cron nell'agent.**
- Tabella `scan_schedules` **non** creata nell'MVP (solo documentata qui): `id, tenant_id, home_id, profile, cron/interval, enabled, next_run_at`.

Nota: esistono job periodici **non di scansione** e ammessi (sync feed NVD/KEV, reaper delle scansioni scadute, pulizia token, rilevazione agent offline da heartbeat mancante). Nessuno di questi tocca la rete dell'utente.
