# 21 — Dashboard Angular (Milestone 12)

La M12 completa la dashboard con le funzioni del backend disponibili fino alla M11. Aggiunge:
- la **panoramica** delle abitazioni, collegata al motore di rischio;
- la pagina delle **vulnerabilità note** dell'abitazione;
- la **mappa di rete**;
- la navigazione **responsive**;
- gli **E2E Playwright**.

Le pagine di funzioni non ancora implementate non sono state create come segnaposto: abbonamento (M17). L'assistente di sicurezza (M16) è la pagina `/homes/:id/assistant` ([25-AI-ASSISTANT.md](25-AI-ASSISTANT.md)). La regola è "nessuna funzionalità finta". Alert e report sono stati aggiunti nella M13 ([22-ALERTS-REPORTS.md](22-ALERTS-REPORTS.md)). L'inventario Home Assistant (M15) è una sezione del dettaglio della scansione, non una pagina ([24-INTEGRATIONS.md](24-INTEGRATIONS.md)).

## 1. Pagine

| Area | Pagina | Percorso |
|---|---|---|
| Accesso | Login | `/login` |
| | Registrazione | `/register` |
| | Password dimenticata | `/forgot-password` |
| | Reset password | `/reset-password` |
| | Verifica email | `/verify-email` |
| | Attiva account | `/accept-invitation` |
| Sicurezza | **Panoramica** (M12, pagina iniziale) | `/overview` |
| | Abitazioni | `/homes` |
| | Dettaglio abitazione | `/homes/:id` |
| | Scansioni | `/homes/:id/scans` |
| | Dispositivi | `/homes/:id/devices` |
| | Problemi di sicurezza | `/homes/:id/findings` |
| | **Vulnerabilità note** (M12) | `/homes/:id/vulnerabilities` |
| | Punteggio di sicurezza | `/homes/:id/risk` |
| | **Mappa di rete** (M12) | `/homes/:id/network-map` |
| | **Report PDF** (M13) | `/homes/:id/reports` |
| Avvisi | **Avvisi** (M13, con contatore da leggere) | `/alerts` |
| | **Preferenze di notifica** (M13) | `/alerts/preferences` |
| Gestione | Utenti | `/users` |
| | Clienti | `/customers` |
| | Organizzazione | `/organization` |
| | Account | `/account` |
| | Stato sistema | `/system-status` |

Tutti i testi sono in italiano e inglese. Il menu mostra solo le voci consentite dai permessi, ma l'autorizzazione resta sempre al backend.

## 2. Panoramica (`/overview`)
- **Dati**: `GET /api/v1/overview` (ADR-065), con le abitazioni visibili all'utente, ordinate dalla più a rischio.
- **Per ogni abitazione**:
  - ultimo punteggio calcolato, livello, giudizio, copertura e variazione;
  - "Provvisorio" se la copertura è bassa;
  - nota se l'ultima scansione era "Solo rilevamento";
  - problemi conteggiati per gravità e vulnerabilità KEV;
  - dispositivi e ultima scansione;
  - link a punteggio, problemi e mappa.
- **Riepilogo**: abitazioni, quante a rischio alto o critico, problemi critici o alti, KEV, abitazioni senza punteggio.
- **Senza `finding:read`** su un'abitazione si vede solo il nome, con il motivo.

## 3. Vulnerabilità note (`/homes/:id/vulnerabilities`)
- **Dati**: `GET /homes/{id}/vulnerabilities` (M11), con le CVE dei finding non risolti, al massimo 500.
- **Ordine**: prima le KEV, poi per CVSS.
- **Filtri**: "solo KEV" e gravità.
- **Per ogni CVE**: EPSS, qualità della corrispondenza, tipo e stato del finding, dispositivo.
- Il link alla scheda NVD si apre in una nuova scheda (`noopener`).
- Ripete la nota che la corrispondenza si basa su prodotto e versione dichiarati dal servizio.

## 4. Mappa di rete (`/homes/:id/network-map`)
- **Dati**: dispositivi, reti dell'abitazione e breakdown dell'ultimo snapshot con punteggio, anche dopo una scansione `DISCOVERY`. Nessun nuovo endpoint.
- **Una stella per rete autorizzata**:
  - il router (categoria `ROUTER`) è al centro; se non è identificato c'è un nodo tratteggiato "Router non identificato";
  - gli altri dispositivi stanno su anelli;
  - i dispositivi fuori dalle reti configurate sono in un gruppo a parte.
- **Colore**: dipende dai punti che il dispositivo toglie all'ultimo punteggio. Verde: 0. Giallo: meno di 15. Rosso: 15 o più.
- **Esposizione**: un arco tratteggiato rosso collega a Internet i dispositivi con un inoltro UPnP.
- **Selezione**: un nodo si seleziona con mouse o tastiera (Invio o Spazio) e mostra i dettagli.
- **Tabella**: ripete gli stessi dati, per lettori di schermo e schermi piccoli.
- **Senza `finding:read`** mostra solo i dispositivi, senza colori di rischio.
- La mappa è **logica** (ADR-065): i collegamenti indicano la rete, non il cablaggio o il Wi-Fi reali. L'SVG è disegnato senza librerie.

## 5. Responsive
- **Sotto 860 px**: il menu si chiude dietro il pulsante ☰ (`aria-expanded`) e si richiude dopo la scelta.
- **Sotto 640 px**:
  - schede a tutta larghezza;
  - le tabelle larghe scorrono dentro la scheda;
  - le liste di dettagli vanno su una colonna.
- La mappa SVG si adatta alla larghezza.
- **Verifica E2E**: nessuno scorrimento orizzontale della pagina su panoramica, punteggio, vulnerabilità e mappa, in desktop e mobile (Pixel 7).

## 6. Test
- **Backend**: `RiskScoreTest`, che estende lo scenario M11 su `/overview`:
  - ultimo punteggio dopo una `DISCOVERY` con il motivo, copertura, dispositivi, ultima scansione;
  - totale dei finding conteggiati;
  - abitazione senza scansioni;
  - nessun dato di un altro tenant.
- **Frontend unit** (Vitest):
  - `overview.page.spec` (2);
  - `vulnerabilities.page.spec` (2);
  - `network-map.page.spec` (4: CIDR IPv4/IPv6, layout senza sovrapposizioni con 32 dispositivi, colori, esposizione, dettagli, permessi).
- **E2E** (Playwright, `e2e/`), con build di produzione e API `[MOCK]`, nei profili desktop e mobile:
  - percorso panoramica → punteggio → vulnerabilità con filtro → mappa con selezione da tastiera, senza errori in console né chiamate non previste;
  - menu su schermi piccoli;
  - passaggio all'inglese.

Comandi (Docker, senza Node locale):
```
docker run --rm -v <dashboard>:/app -w /app node:24-alpine npx ng build
docker run --rm --ipc=host -v <dashboard>:/app -w /app mcr.microsoft.com/playwright:v1.65.1-noble npm run e2e
```

## 7. Limiti
- **Topologia**: la mappa non mostra la topologia fisica e non distingue Wi-Fi e cavo.
- **Abitazioni con molti dispositivi**: gli anelli crescono e le etichette si accorciano; la tabella resta completa.
- **E2E**: non usano il backend reale; il flusso completo con agent e LAN autorizzata resta nella verifica della M18.
- **Client API**: è ancora scritto a mano (servizi in `core/*`). La generazione da OpenAPI prevista in docs/01 §6 non è stata introdotta: sarebbe un refactoring fuori ambito.
