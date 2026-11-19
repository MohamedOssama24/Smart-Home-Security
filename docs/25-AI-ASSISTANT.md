# 25 — Assistente di sicurezza (Milestone 16)

Assistente in sola lettura per una casa: risponde a domande su punteggio, problemi e dispositivi **solo con i dati del tenant**, cita le fonti, non esegue azioni e non salva nulla. Decisione: ADR-071.

## Flusso

1. `POST /api/v1/homes/{homeId}/assistant/questions` `{question, locale}` (docs/05).
2. In una transazione del tenant: abitazione (404 se di altri), `device:read` + `finding:read`, limite 20/minuto per utente (429), caricamento dei fatti.
3. Fuori dalla transazione: il provider configurato risponde.
4. Se il provider non è LOCAL, la risposta passa da `GroundingValidator`; se non passa o il provider fallisce, si usa la risposta LOCAL (`fallback=true`, `fallbackReason` = `NOT_GROUNDED` | `PROVIDER_UNAVAILABLE`).
5. Audit `ASSISTANT_QUERY` (provider, fallback, lunghezza della domanda, numero di citazioni; mai il testo).

## Fatti (`AssistantContextLoader`)

| Id | Fonte | Contenuto |
|---|---|---|
| `S1` | ultimo `risk_snapshots` della casa | punteggio, livello, rating, copertura, provvisorio, motivo se non calcolato |
| `F1…F100` | `ReportRepository.findings` (come il PDF) | titolo e raccomandazione localizzati, severità, stato, dispositivo, IP |
| `D1…D150` | `ReportRepository.devices` | nome, IP, categoria, produttore |

I testi che arrivano dalla LAN (hostname, produttori) sono dati non fidati: caratteri di controllo/formato e link rimossi, massimo 160 caratteri. Oltre i limiti, `truncated=true`.

## Provider

| Provider | Configurazione | Note |
|---|---|---|
| `LOCAL` (predefinito) | `SHSC_ASSISTANT_PROVIDER=LOCAL` | deterministico, offline. Intenti IT/EN: richiesta di azione (rifiutata), dispositivo (per IP esatto o nome), cosa sistemare, rischio, dispositivi, riepilogo |
| `OLLAMA` | `SHSC_ASSISTANT_PROVIDER=OLLAMA`, `SHSC_OLLAMA_URL`, `SHSC_OLLAMA_MODEL` (default `llama3.2`) | LLM self-hosted gratuito, `HttpClient` del JDK: niente redirect, niente proxy, timeout 30 s, risposta max 512 KB, temperatura 0, output JSON `{answer, citations}`. DATA e QUESTION viaggiano codificati in JSON; il prompt di sistema li dichiara non fidati |
| Cloud (es. Claude) | — | non incluso: costo e invio dei dati a terzi. Richiede un ADR dedicato con l'SDK ufficiale |

Un provider sconosciuto o non configurato ricade su LOCAL (log di avviso all'avvio).

## Anti-allucinazione (`GroundingValidator`)

Rifiuta una risposta se: vuota, più di 4000 caratteri, caratteri di controllo, citazione di un id inesistente, nessuna citazione quando ci sono fatti, IP non presente nei fatti, CVE non presente, link non presente, `N/100` diverso dal punteggio.

## Dashboard

Pagina `/homes/:id/assistant` (link dal dettaglio casa): domanda libera o suggerita, risposta con chip delle fonti, provider, eventuale fallback e data dei dati. Avviso fisso: sola lettura, nessuna azione, niente salvato. IT/EN.

## Test

- `AssistantGroundingTest` (unit, fixture [MOCK]): risposte LOCAL validate e con citazioni, azioni rifiutate, nessun dato inventato senza scansioni, validatore contro IP/CVE/link/punteggi/citazioni inventati, prompt injection nei nomi, provider Ollama contro un server HTTP simulato.
- `AssistantIntegrationTest`: endpoint reale con scansione [MOCK] (Telnet), nessuna scansione avviata da "Avvia una scansione", validazione, READ_ONLY, isolamento tra tenant, audit senza testo.
- `assistant.page.spec.ts`: invio, fonti, fallback, errori.

## Limiti

- Ollama verificato solo con un server simulato, non con un modello reale.
- Nessuna conversazione multi-turno: ogni domanda è indipendente.
- LOCAL riconosce un insieme finito di intenti; per le altre domande risponde con un riepilogo.
- Il limite di frequenza è in memoria (per istanza).
