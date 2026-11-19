# 17 — Fingerprinting e classificazione dei dispositivi (Milestone 8)

Trasforma le osservazioni di una scansione ([16-NETWORK-DISCOVERY.md](16-NETWORK-DISCOVERY.md)) in un **inventario dell'abitazione**: un dispositivo per MAC, con valori stimati, livello di affidabilità per campo, fonti, categoria e storico. Il modello di riferimento è [07-DISCOVERY-FINGERPRINTING.md](07-DISCOVERY-FINGERPRINTING.md) §2–3; questo documento descrive ciò che è implementato.

## 1. Quando gira
- Alla chiusura di una scansione `COMPLETED` / `COMPLETED_WITH_WARNINGS` e dopo un upload tardivo (`LATE_UPLOAD`), **nella stessa transazione** della transizione di stato: inventario e scansione restano coerenti.
- Nessun traffico aggiuntivo verso i dispositivi: usa solo ciò che la discovery ha già raccolto.
- Le osservazioni vengono collegate al dispositivo (`scan_observations.device_id`).

## 2. Identità e MAC randomizzati
- Identità: `(home, MAC)`; senza MAC (host visto solo via router/IPv6) `(home, IP)`.
- **MAC randomizzato**: bit "locally administered" (`primo ottetto & 0x02`). Marcato `mac_randomized`, **il registro OUI non viene consultato** (il prefisso non identifica un produttore). Se un altro dispositivo della stessa abitazione ha lo stesso nome, è indicato come `probable_same_as` ("probabilmente lo stesso dispositivo"): solo un'indicazione, i due record non vengono uniti.

## 3. Registro OUI (IEEE)
- Tabella globale `oui_entries` (dato pubblico, senza tenant): MA-L (24 bit), MA-M (28), MA-S (36); ricerca per prefisso più lungo.
- **Sincronizzazione manuale**: `POST /api/v1/platform/oui/sync`, solo amministratori di piattaforma (`platform:admin`), registrata in audit (`OUI_REGISTRY_SYNCED`). Nessun job automatico.
- Sorgenti: i 3 CSV pubblici IEEE (gratuiti, senza account), configurabili con `SHSC_OUI_SOURCES` (es. mirror interno). Solo HTTPS; HTTP solo verso loopback. Limiti: 16 MB per file, 60 s.
- Tutti i file vengono scaricati e letti **prima** di toccare il database; la sostituzione avviene in una sola transazione. Un file mancante, vuoto o troppo grande → `502` con codice (`OUI_SOURCE_UNAVAILABLE`, `OUI_SOURCE_EMPTY`, `OUI_SOURCE_TOO_LARGE`, `OUI_SOURCE_INVALID`, `OUI_SOURCE_NOT_ALLOWED`) e registro invariato.
- Il produttore da OUI è quello **della scheda di rete**: indizio debole (affidabilità L), mai sufficiente da solo.
- Differenza da docs/07: la ricerca OUI avviene nel backend; la distribuzione di uno snapshot all'agent non serve e non è implementata.

## 4. Regole e punteggi
Ruleset versionato in `backend/spring-boot-api/src/main/resources/fingerprint/rules.json` (versione `2026.11-1`, 47 regole; dalla M9 `2026.11-2`, 60 regole con gli indizi di porte e servizi, vedi [18-PORT-SCANNING.md](18-PORT-SCANNING.md) §7), validato all'avvio: un ruleset non valido blocca l'avvio invece di classificare male (id duplicati, regole che concludono "sconosciuto", un indizio debole che da solo raggiunge la soglia).

| Forza | Peso | Esempi |
|---|---|---|
| `STRONG` | 60 | servizio mDNS `_ipp._tcp` (stampante), modello mDNS `iPhone…`, router dell'integrazione TR-064/SNMP |
| `MODERATE` | 30 | tipo UPnP `Printer`, `InternetGatewayDevice`, nome `diskstation`, `_hap._tcp` + OUI Espressif/Tuya |
| `WEAK` | 10 | solo OUI di un produttore di telecamere, nome `camera-…`, `android-…` |

Campi su cui le regole lavorano: `hostname`, `oui`, `method`, `router.self`, `mdns.service`, `mdns.model`, `mdns.maker`, `mdns.txt.ty`, `ssdp.type`, `ssdp.manufacturer`, `ssdp.product`. Ogni condizione è un'espressione regolare (senza distinzione maiuscole/minuscole); una regola con più condizioni richiede tutte.

**Decisione** (soglia 50):
- una categoria è scelta solo se raggiunge la soglia **e** ha un indizio `STRONG`, oppure due `MODERATE` da **fonti diverse** (due indizi dalla stessa fonte non sono indipendenti);
- `STRONG` confermato da un altro indizio non debole di fonte indipendente → affidabilità **alta**; altrimenti **media**;
- un'altra categoria che si qualifica abbassa l'affidabilità di un livello (`conflicts`); **parità di punteggio → `UNKNOWN_DEVICE`**;
- solo indizi deboli (anche più d'uno) → `UNKNOWN_DEVICE`, ma le regole corrispondenti sono comunque salvate e mostrate ("perché").

Il risultato (`classification` jsonb) contiene categoria, affidabilità, punteggio, regole corrispondenti con fonti e valori, conflitti e versione del ruleset.

## 5. Affidabilità per campo
Ogni campo (`IP`, `MAC`, `HOSTNAME`, `MANUFACTURER`, `MODEL`, `OS`, `DEVICE_TYPE`) è salvato in `device_identifications` con valore, affidabilità, elenco delle fonti (`source`, `value`, `reliability` L/M/H, `agrees`) e flag `conflict`.
- Una fonte H → **alta**; una fonte M, o almeno due fonti concordanti → **media**; altrimenti **bassa**.
- Un gruppo di valori in disaccordo con almeno una fonte M/H → `conflict = true` e affidabilità abbassata di un livello.
- Produttori confrontati per prima parola ("Synology Inc." = "Synology"); nomi per prima etichetta. I nomi non sono mai in conflitto: tutte le varianti restano visibili con la loro fonte.
- `FIRMWARE` non viene stimato in questa milestone.
- Affidabilità complessiva: alta se tipo alto e produttore almeno medio; media se tipo almeno medio; altrimenti bassa.

## 6. Sistema operativo (base)
| Indizio | Valore | Affidabilità |
|---|---|---|
| mDNS `osxvers` / modello Mac, iPhone, iPad | MACOS / IOS | M |
| intestazione `SERVER` SSDP (Windows / Android / Linux) | WINDOWS / ANDROID / LINUX | L |
| `sysDescr` SNMP con Linux | EMBEDDED_LINUX | L |
| NetBIOS, nome `DESKTOP-xxxxxxx` | WINDOWS | L |
| nome `android-…` | ANDROID | L |
| TTL ≤ 64 | conferma solo un sistema Unix indicato da un'altra fonte | L |
| TTL 65–128 / > 128 | WINDOWS / EMBEDDED_LINUX | L |

Il TTL da solo non supera mai l'affidabilità bassa.

## 7. Classificazione manuale e storico
- `PUT /api/v1/devices/{id}/category` `{"category": "NAS"}` imposta la categoria manuale, `{"category": null}` la rimuove. Permesso `device:classify` (tutti i ruoli tranne `READ_ONLY`); categoria sconosciuta → `400 INVALID_CATEGORY`; audit `DEVICE_CATEGORY_CHANGED`.
- La scelta manuale **non viene mai sovrascritta** dalle scansioni successive. Se una scansione rileva con affidabilità media/alta una categoria diversa, la risposta la riporta come `suggestedCategory` (solo suggerimento).
- `device_category_changes`: ogni cambio, `AUTO` (prima rilevazione o categoria rilevata cambiata, con la scansione) o `MANUAL` (con l'utente). Il database impone che solo i cambi manuali abbiano un autore.

## 8. API e dashboard
- `GET /api/v1/homes/{homeId}/devices` (`device:read`), `GET /api/v1/devices/{id}` (con identificazioni e storico), `PUT /api/v1/devices/{id}/category`.
- `GET /api/v1/platform/oui` (stato dei registri) e `POST /api/v1/platform/oui/sync` (solo `platform:admin`).
- Dashboard: pagina **Dispositivi** dell'abitazione (`/homes/:id/devices`): elenco con categoria, affidabilità, MAC casuale; dettaglio con campi identificati, fonti in disaccordo, regole che hanno portato alla categoria, scelta manuale, suggerimento e storico. Testi IT/EN.

## 9. Test
- `ClassificationRulesTest`: positivi (stampante, router, NAS, iPhone, IoT) e negativi "indizio debole" (solo OUI, due deboli, due medi dalla stessa fonte, `_hap` senza OUI), conflitto e parità, ruleset non valido rifiutato.
- `FieldResolverTest`: affidabilità per campo, conflitti, TTL, OS, MAC randomizzati.
- `OuiRegistryParserTest`: CSV IEEE (virgolette, righe su più linee, registri e righe non valide scartati).
- `OuiSyncTest`: server HTTP **[MOCK]** su loopback; sostituzione solo se tutti i file sono letti; HTTP verso altri host rifiutato senza connessione; 403 per i non amministratori di piattaforma.
- `DeviceInventoryTest`: due scansioni **[MOCK]** end-to-end via API, classificazione manuale mantenuta, suggerimento, `probable_same_as`, permessi e isolamento tra tenant.

## 10. Limiti
- Il registro OUI è vuoto finché un amministratore non esegue la sincronizzazione: fino ad allora il produttore da OUI non è disponibile (gli altri indizi funzionano).
- Le regole coprono le categorie più comuni; porte e servizi (M9) aggiungeranno indizi (RTSP, banner).
- Nessuna correlazione automatica tra MAC randomizzati oltre al nome uguale.
