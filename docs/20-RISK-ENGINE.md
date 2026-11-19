# 20 — Motore di rischio (Milestone 11)

Dopo l'analisi di sicurezza ([19-SECURITY-ANALYSIS.md](19-SECURITY-ANALYSIS.md)) il backend calcola il **punteggio di sicurezza** di un'abitazione, 0–100 (100 = nessun problema noto), insieme alla **copertura** della scansione su cui si basa. Ogni calcolo è salvato come snapshot spiegabile, con il delta rispetto al precedente. Il modello è quello di [09-SECURITY-ANALYSIS-RISK.md](09-SECURITY-ANALYSIS-RISK.md) §3; le differenze sono motivate in ADR-059…ADR-063.

## 1. Quando si calcola
- **Alla chiusura di una scansione** (`SCAN`): nella stessa transazione, dopo fingerprinting e analisi. Vale anche per i risultati arrivati in ritardo (`LATE_UPLOAD`). Una scansione annullata o fallita non produce snapshot.
- **Dopo un triage** (`TRIAGE`): solo se un finding entra o esce dai conteggiati (`OPEN`/`ACKNOWLEDGED` ↔ `FALSE_POSITIVE`/`ACCEPTED_RISK`). Usa la stessa scansione e la stessa copertura dell'ultimo snapshot calcolato. Il passaggio `OPEN` ↔ `ACKNOWLEDGED` non cambia il punteggio e non crea snapshot.
- **Scansione `DISCOVERY`**: senza dati di porte il punteggio non è calcolato (`score` nullo, `notComputedReason = PORT_SCAN_REQUIRED`). La copertura è comunque registrata e l'API restituisce anche l'ultimo snapshot con punteggio.
- Gli snapshot non vengono mai riscritti. Ognuno registra `engine_version` (oggi `2026.11-1`): cambiare i pesi richiede una nuova versione.

## 2. Punteggio (`RiskEngine`)
```
deduzione = base(gravità) × tipo × affidabilità × criticità dispositivo × esposizione × KEV
base:        CRITICAL 30 · HIGH 15 · MEDIUM 6 · LOW 2 · INFORMATIONAL 0
tipo:        CONFIRMED 1.0 · POTENTIAL 0.6 · SUSPICIOUS 0.5 · UNVERIFIED 0
affidabilità: HIGH 1.0 · MEDIUM 0.8 · LOW 0.5
criticità:   ROUTER, NAS, IP_CAMERA 1.3 · LAPTOP, DESKTOP 1.1 · altri (anche non identificati) 1.0
esposizione: 1.5 se il dispositivo ha un finding upnp.exposed-mapping non risolto e non escluso
KEV:         1.5 se la CVE del finding è nel catalogo KEV al momento del calcolo
per dispositivo: min(Σ deduzioni, 45)
punteggio = floor(max(0, 100 − Σ dispositivi))
```
- **Contano** i finding `OPEN` e `ACKNOWLEDGED`. `FALSE_POSITIVE` e `ACCEPTED_RISK` sono elencati a parte (`excluded`); i `RESOLVED` non ci sono.
- I finding con deduzione 0 (informativi o da verificare, come `device.unknown`) sono solo contati (`notScored`). **Un dispositivo non identificato non è penalizzato in quanto tale**: conta solo ciò che espone.
- **Arrotondamento per difetto**: una deduzione piccola non sparisce (99,5 → 99).
- Contano anche i finding aperti di dispositivi non visti dall'ultima scansione: non sono risolti, perché nessuna scansione li ha ricontrollati.

## 3. Copertura
```
copertura = 0.40 × (dispositivi analizzati / dispositivi visti)
          + 0.25 × profilo (DISCOVERY 0.2 · QUICK 0.6 · STANDARD 0.85)
          + 0.20 × tecniche riuscite (ARP 0.4 · ICMP 0.2 · mDNS 0.2 · SSDP 0.2)
          + 0.15 × integrazione router (1 se TR-064 o SNMP hanno risposto)
```
- **Dispositivi visti**: quelli dell'inventario visti da questa scansione. **Analizzati**: quelli con il riepilogo `PORTSCAN` non in pausa.
- Una tecnica non è riuscita se l'agent ha segnalato `<TECNICA>_UNAVAILABLE`.
- Il profilo `DEEP` non esiste ancora; il peso 1.0 resta nel modello.
- **Contro la falsa sicurezza**:
  - copertura < 0.6: punteggio limitato a 70 e marcato *provvisorio*;
  - copertura < 0.8: il giudizio non può essere "Ottimo".
- Esempi:
  - una scansione STANDARD completa senza router vale 0.81;
  - una QUICK completa vale 0.75.

## 4. Livello e giudizio
- **Livello di rischio**: ≥ 85 `LOW` · 65–84 `MEDIUM` · 40–64 `HIGH` · < 40 `CRITICAL`.
- **Giudizio** (ADR-060):
  - `LOW` → `EXCELLENT` se la copertura è ≥ 0.8 e il punteggio non è provvisorio, altrimenti `GOOD`;
  - `MEDIUM` → `FAIR`;
  - `HIGH` → `POOR`;
  - `CRITICAL` → `CRITICAL`.

## 5. Snapshot (`risk_snapshots`, `V011__risk_engine.sql`, RLS)
- **Colonne**: `trigger`, `score`, `risk_level`, `rating`, `not_computed_reason`, `coverage`, `coverage_detail` (dispositivi, profilo, tecniche, router, componenti), `provisional`, `breakdown`, `top_devices`, `delta_from_previous`, `engine_version`.
- **`breakdown`**:
  - ogni deduzione (finding, dispositivo, titolo e parametri i18n, fattori, valore), al massimo 100, ordinate per valore;
  - gli id di tutti i finding conteggiati (fino a 1000), usati per il delta;
  - i totali per dispositivo (grezzo, applicato, limitato), gli esclusi, `notScored`, `uncappedScore`.
- **`delta_from_previous`**: confronto con l'ultimo snapshot calcolato:
  - variazione di punteggio e di copertura;
  - nuovi finding conteggiati;
  - finding non più conteggiati, con lo stato attuale (`RESOLVED`, `FALSE_POSITIVE`, `ACCEPTED_RISK`, `REMOVED`);
  - nuovi dispositivi (prima volta visti in questa scansione).
  - Ogni elenco ha al massimo 20 voci, più il totale.
- **Limiti di dimensione**: se un documento supera il limite, i parametri dei finding vengono omessi.

## 6. API
| Metodo | Percorso | Note |
|---|---|---|
| GET | `/api/v1/homes/{homeId}/risk` | `current` (ultimo snapshot, anche non calcolato) e `lastScored` (ultimo con punteggio); `null` se non ci sono scansioni |
| GET | `/api/v1/homes/{homeId}/risk/history?limit=` | snapshot dal più recente, senza breakdown; `limit` 1–100 (default 30, altrimenti `400 INVALID_LIMIT`) |
| GET | `/api/v1/homes/{homeId}/vulnerabilities` | CVE abbinate ai dispositivi della casa (finding non risolti): KEV, CVSS, EPSS, qualità del match, dispositivo, stato del finding; al massimo 500 |

Permesso `finding:read` (ADR-059). Un'abitazione di un altro tenant restituisce 404.

## 7. Dashboard
Pagina **"Punteggio di sicurezza"** (`/homes/:id/risk`, link dal dettaglio abitazione):
- punteggio, livello e giudizio;
- avviso "provvisorio" con il limite e il valore senza limite;
- copertura con le sue componenti e il suggerimento per aumentarla;
- **"Perché questo punteggio?"**: ogni deduzione con i fattori, gli esclusi, il limite per dispositivo;
- dispositivi più a rischio, "Cosa è cambiato", storico;
- messaggio dedicato dopo una scansione `DISCOVERY`, che mostra l'ultimo punteggio calcolato.

Testi IT/EN.

## 8. Test
- **`RiskEngineTest`** (8): copertura e sue componenti, nessun dispositivo, copertura bassa (limite 70, provvisorio), copertura media (non "Ottimo"), `DISCOVERY` senza punteggio, dispositivo sconosciuto non penalizzato, fattori moltiplicati e limite per dispositivo, falsi positivi e rischi accettati esclusi (anche dall'esposizione), soglie dei livelli.
- **`RiskScoreTest`** (scenario via API, dispositivo e CVE [MOCK]):
  - STANDARD, poi QUICK (telnet 23 risolto, 2323 non coperto), con verifica di breakdown, copertura e delta;
  - triage `FALSE_POSITIVE` (snapshot `TRIAGE`) e `ACKNOWLEDGED` (nessuno snapshot);
  - `DISCOVERY` non calcolata, storico, `limit` non valido;
  - CVE della casa, altro tenant 404.
- **Frontend**: `risk.page.spec` (4).

## 9. Limiti
- Pesi iniziali da docs/09, da tarare con dati reali (M18). Doppio peso KEV, vedi ADR-062.
- L'integrazione router conta solo TR-064/SNMP configurati dal proprietario; UPnP IGD non è un'integrazione.
- Il punteggio non cambia se il catalogo KEV si aggiorna senza una nuova scansione o un nuovo triage.
- L'alert sul calo del punteggio (`SCORE_DROPPED`) è stato aggiunto nella M13 ([22-ALERTS-REPORTS.md](22-ALERTS-REPORTS.md)). La pagina delle CVE della casa e la mappa di rete sono state aggiunte nella M12 ([21-DASHBOARD.md](21-DASHBOARD.md)).
