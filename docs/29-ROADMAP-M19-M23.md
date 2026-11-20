# 29 — Roadmap M19–M24: inventario, identificazione, sicurezza, monitoraggio, immagini, persone

Roadmap approvata il 19/11/2026. Nessuna milestone avviata: M19 parte solo su autorizzazione esplicita.

**Ordine**: M19 → M20 → M21 → M22. M23 dipende solo da M20 e può procedere in parallelo a M21–M22.

## Punto di partenza (analisi del 19/11/2026)

| Area | Già presente | Mancante |
|---|---|---|
| Inventario | discovery ARP/ICMP/mDNS/SSDP-UPnP/NDP/NetBIOS; `devices.mac` (uno solo), `addresses inet[]`, `mac_randomized`, `probable_same_as`; OUI; tabelle del router | interfacce, più MAC per dispositivo, storico indirizzi, raggruppamento IPv6 temporanei |
| Identificazione | `manufacturer`, `model`, `hostname`; `device_identifications` con fonti e confidenza (campo `FIRMWARE` già previsto, ma un solo valore per campo) | firmware (solo IPP), codice prodotto, nome personalizzato, CPE, storico identificazioni, stato verificato/probabile/sconosciuto |
| Immagini | nessuna | catalogo modelli, licenze, fallback per categoria |
| CVE | NVD/KEV/EPSS; `device_vulnerabilities.match_quality` | match su firmware/CPE del dispositivo; nuovo confronto dopo l'aggiornamento dei feed |
| Spiegazioni | `title_key` / `recommendation_key` per le regole; `finding_evidence` | spiegazione e rimedio specifici per le CVE |
| Avvisi | canali DASHBOARD/EMAIL/PUSH, preferenze, consegne; tipi NEW_FINDING, NEW_DEVICE, SCORE_DROPPED, AGENT_OFFLINE… | scansioni programmate, avvisi su nuove CVE e firmware, riepiloghi, storico notifiche consultabile; FCM mai provato su dispositivo reale |

## M19 — Inventario e storico indirizzi

- **Stato**: implementata il 19/11/2026, in attesa di approvazione (ADR-074). Manca la prova E2E sulle VM di `172.20.204.0/22`.
- **Priorità**: alta. **Dipendenze**: nessuna.
- **Funzionalità**: tabelle `device_interfaces` (MAC, tipo, fonte) e `device_addresses` (IPv4/IPv6, ambito globale/link-local/temporaneo, prima/ultima rilevazione, scansione); storico degli indirizzi; unione di più MAC sullo stesso dispositivo; MAC da indirizzi IPv6 EUI-64; dettaglio interfacce, indirizzi attuali e storico in web e app.
- **Riuso**: pipeline `discovery`, `probable_same_as`, OUI, `router.go`.
- **Rischi tecnici**: gli IPv6 temporanei fanno crescere lo storico (serve una conservazione limitata); con MAC casuali si rischiano unioni sbagliate, quindi l'unione resta "probabile" finché l'utente non la conferma.
- **Criteri di completamento**: un dispositivo dual-stack nelle VM di `172.20.204.0/22` mostra tutti gli IPv4/IPv6, i MAC e le interfacce; lo storico registra i cambi di indirizzo tra due scansioni; test RLS verdi sulle nuove tabelle; unit test di unione ed EUI-64 verdi.

## M20 — Identificazione e scheda dispositivo

> **Stato**: implementata (backend, agent, dashboard web, app Flutter in sola lettura), in attesa di approvazione; decisioni in ADR-076. Manca: SNMP, solo con community inserita dall'utente e senza credenziali predefinite (mai `public`). Prove E2E su VM ancora da eseguire (vedi PROJECT_STATUS, M20 → Limiti).

- **Priorità**: alta (base per M21–M23). **Dipendenze**: M19.
- **Funzionalità**: nome personalizzato, produttore, modello, codice prodotto, firmware, CPE; per ogni campo stato **Verificato / Probabile / Sconosciuto**, con fonte e confidenza visibili in web e app; storico delle identificazioni (prerequisito per rilevare i cambi di firmware in M22); fonti aggiuntive: descrittore UPnP completo, TXT mDNS, Home Assistant, IPP; SNMP solo con community inserita dall'utente, mai credenziali di default.
- **Regola "Verificato"**: dato dichiarato dal dispositivo, oppure confermato dall'utente, oppure due fonti **indipendenti** concordanti. Due fonti sono indipendenti solo se non derivano dalla stessa informazione originaria: ad esempio il nome mDNS e il nome che il router ha ricevuto dallo stesso annuncio sono la stessa fonte, così come due dati ricavati dallo stesso OUI o dallo stesso banner. Ogni fonte registra la propria origine per poterlo verificare.
- **Riuso**: `device_identifications` (fonti, confidenza, conflitti), motore di classificazione con regole versionate, `ipp.go`.
- **Rischi tecnici**: fonti eterogenee e contraddittorie; mapping CPE ambiguo per l'IoT (in caso di dubbio resta "Probabile"); firmware spesso non esposto (molti campi resteranno "Sconosciuto").
- **Criteri di completamento**: 0 valori "Verificato" errati sul dataset di riferimento (dati MOCK etichettati); test che due fonti con la stessa origine non producano "Verificato"; conflitto tra fonti → "Probabile"; il nome personalizzato non viene mai sovrascritto da una scansione.

## M21 — Problemi di sicurezza e CVE

- **Priorità**: alta. **Dipendenze**: M20.
- **Funzionalità**: per ogni problema gravità, CVE associate (se presenti), evidenze (`finding_evidence`), spiegazione comprensibile IT/EN e istruzioni concrete (aggiornare il firmware con link al supporto del produttore, disattivare il servizio, isolare il dispositivo); match CVE sul firmware/CPE del dispositivo; priorità da CVSS + KEV + EPSS.
- **Riduzione dei falsi positivi**: CVE **confermata** solo con CPE "Verificato" e versione nell'intervallo vulnerabile; con versione assente o dato "Probabile" il problema appare come **"da verificare"**, separato e senza effetto sul punteggio di rischio.
- **Esclusioni segnalate dagli utenti**: ogni esclusione di una CVE è legata a un dispositivo e a un tenant (RLS), registra chi, quando e perché nell'audit log, è reversibile (riattivabile con storico) e non influisce su altri dispositivi o tenant.
- **Riuso**: `vulnintel`, `match_quality`, `findings` con chiavi i18n, stato `FALSE_POSITIVE`, `risk`, report PDF.
- **Rischi tecnici**: versioni non standard (backport, firmware personalizzati); intervalli NVD incompleti; spiegazioni generiche se manca la CWE.
- **Criteri di completamento**: 0 falsi positivi tra le CVE confermate **sul dataset di riferimento**. Non è una garanzia di accuratezza assoluta sui dispositivi reali, dove la precisione dipende dai dati esposti e dai feed. Ogni problema mostra gravità, evidenze, spiegazione e rimedio; i18n IT/EN completa; esclusioni isolate per dispositivo/tenant, reversibili e presenti nell'audit; test di non regressione su risk e report verdi.

## M22 — Monitoraggio continuo e notifiche

- **Priorità**: alta. **Dipendenze**: M20 (cambi firmware), M21 (nuove CVE).
- **Scansioni automatiche**:
  - frequenza configurabile per abitazione, entro i limiti del piano;
  - limiti di carico: una scansione alla volta per agent, scansioni distribuite nel tempo e tetto giornaliero per abitazione/tenant;
  - sospensione e ripresa manuale da parte dell'utente, e sospensione automatica in caso di errori ripetuti;
  - controlli di permesso: solo ruoli con permesso di scansione possono configurare la frequenza o sospendere; prima di ogni esecuzione si verificano rete autorizzata e agent online.
- **Funzionalità**: nuovo confronto con l'inventario dopo ogni aggiornamento dei feed; avvisi `NEW_CVE_ON_DEVICE`, `FIRMWARE_CHANGED`, `FIRMWARE_OUTDATED`, `KEV_ADDED`; deduplica, riepilogo periodico, ore di silenzio; storico notifiche consultabile con stato di consegna per canale.
- **Riuso**: `AlertService`, `AlertJobs`, `AlertMailer`, `alerts/push`, `notification_preferences`, `ScanRequestService`, connettività degli agent.
- **Rischi tecnici**: carico su agent e rete; troppe notifiche; FCM non ancora provato su un dispositivo reale.
- **Criteri di completamento**: una scansione programmata parte da sola, rispetta frequenza e limiti, si ferma quando è sospesa e rifiuta le richieste di ruoli senza permesso; una CVE MOCK aggiunta al feed genera un avviso senza nuova scansione; un cambio di firmware simulato genera un avviso; nessun duplicato; storico coerente con le consegne; push ricevuto su un dispositivo reale (serve il progetto Firebase del titolare).

## M23 — Immagini dei dispositivi

- **Priorità**: media. **Dipendenze**: M20.
- **Funzionalità**: catalogo modelli con immagini reali preferite, ciascuna con fonte, licenza verificabile, autore e attribuzione; icona generica per categoria come fallback; foto caricata dall'utente (opzionale); archiviazione locale senza link diretti a siti esterni. Prima dello sviluppo serve un ADR sulla fonte delle immagini.
- **Riuso**: caricamento e validazione del branding (M17), CSP di nginx.
- **Rischi tecnici**: licenze da verificare una per una (es. Wikimedia Commons); bassa copertura dei modelli IoT; sanificazione degli SVG caricati; aggiornamento della CSP.
- **Criteri di completamento**: ogni immagine del catalogo ha licenza registrata e verificabile con attribuzione visibile; un modello non riconosciuto mostra sempre l'icona della sua categoria; validazione di tipo e dimensione e CSP coperte da test.

## M24 — Associazione dispositivo-persona

> Aggiunta il 19/11/2026 per coprire l'obiettivo 4 (dispositivo ↔ persona), non previsto nella prima stesura della roadmap.

- **Priorità**: media. **Dipendenze**: M20 (scheda dispositivo, nome personalizzato, conferme e storico).
- **Funzionalità**: elenco delle persone dell'abitazione (solo etichetta e, facoltativo, collegamento a un account esistente); assegnazione e rimozione manuale di un dispositivo a una persona da web, con visualizzazione in web e app; suggerimenti solo da fonti autorizzate e già collegate dall'utente: entità `person` di Home Assistant e nome del dispositivo nel router o nel DHCP. Un suggerimento resta "Probabile" e non viene mai applicato senza conferma; ogni associazione mostra fonte e stato.
- **Privacy**: minimizzazione (nessuna posizione, nessuna cronologia di presenza, nessuna inferenza dal traffico); nessun tracciamento fuori dalle reti autorizzate; visibilità secondo i ruoli; audit di ogni assegnazione; cancellare una persona rimuove le sue associazioni; testo informativo per gli altri membri della casa.
- **Riuso**: conferme e storico di M20, integrazione Home Assistant, RLS per abitazione, audit.
- **Rischi tecnici**: dati personali (GDPR); MAC casuali che spezzano l'associazione (si appoggia all'inventario M19); dispositivi condivisi da più persone.
- **Criteri di completamento**: assegnazione e rimozione manuale con audit e isolamento RLS provati da test; un suggerimento MOCK da Home Assistant o dal router compare come "Probabile" e diventa definitivo solo dopo conferma; nessun dato di presenza salvato; la cancellazione di una persona rimuove le associazioni; web e app mostrano la persona assegnata.

## Rischi trasversali

- Prove su dispositivi reali solo su reti autorizzate: oggi solo le VM in `172.20.204.0/22`.
- Nuove dipendenze (SNMP, sanificazione SVG) richiedono un ADR.
- Spiegazioni basate su modelli di testo, senza servizi di IA a pagamento.
- Restano dalla M18: Stripe test mode reale, scansione su LAN reale, FCM su dispositivo (chiuso in M22).
