# 19 — Analisi di sicurezza e vulnerabilità (Milestone 10)

Dopo porte e servizi ([18-PORT-SCANNING.md](18-PORT-SCANNING.md)) il backend valuta ciò che una scansione ha osservato e produce i **finding**: problemi di sicurezza con tipo, gravità, affidabilità, evidenze e raccomandazione. Il modello di riferimento è [09-SECURITY-ANALYSIS-RISK.md](09-SECURITY-ANALYSIS-RISK.md) §1–2. Questo documento descrive ciò che è implementato e le differenze, motivate in ADR-054…ADR-058. Punteggio di rischio, copertura, snapshot e delta: [20-RISK-ENGINE.md](20-RISK-ENGINE.md) (M11).

## 1. Quando e su cosa
- L'analisi (`findings/SecurityAnalyzer`) gira **alla chiusura di ogni scansione**, nella stessa transazione, subito dopo il fingerprinting (anche per l'upload tardivo).
- Considera solo i dispositivi **visti da quella scansione** (`devices.last_scan_id`); i loro dati arrivano dalle reti autorizzate, perché i risultati fuori ambito sono già scartati all'ingestione. Nessuna richiesta viene inviata ai dispositivi: l'analisi legge solo ciò che è già stato raccolto (porte, servizi, evidenze, dati UPnP del router).
- Le nuove CVE sincronizzate si applicano dalla scansione successiva: le scansioni passate non vengono rianalizzate (ADR-057).

## 2. Feed pubblici (Vulnerability Intelligence)
| Feed | Sorgente (configurabile) | Cosa si salva |
|---|---|---|
| NVD | CVE API 2.0 (`SHSC_NVD_URL`), API key gratuita opzionale (`SHSC_NVD_API_KEY`, mai nei log) | per ogni prodotto CPE del dizionario: CVE, CVSS (v4.0 > v3.1 > v3.0 > v2, metrica Primary), CWE, riferimenti http(s), descrizione inglese, criteri CPE vulnerabili |
| CISA KEV | JSON ufficiale (`SHSC_KEV_URL`) | data di inserimento, scadenza, uso in ransomware |
| FIRST EPSS | API (`SHSC_EPSS_URL`) | punteggio e percentile delle sole CVE salvate (lotti da 100) |

- **Solo su richiesta** di un amministratore di piattaforma (`POST /api/v1/platform/vulnerabilities/sync`, 202): nessuna sincronizzazione automatica, nessun dato dell'utente inviato all'esterno (ADR-054). Una sola sincronizzazione alla volta (`409 SYNC_ALREADY_RUNNING`); gira in background con pausa tra le richieste NVD (`SHSC_NVD_REQUEST_DELAY`, 6 s senza API key).
- NVD: query `virtualMatchString=cpe:2.3:*:<vendor>:<product>` per prodotto del dizionario, tutte le pagine (al massimo 10 pagine da 2000 per prodotto, `shsc.vulnerabilities.max-pages-per-product`), poi **sostituzione del mirror in un'unica transazione** (le CVE non più restituite, es. respinte, vengono rimosse).
- HTTPS obbligatorio (HTTP solo verso loopback, per i test), limite di dimensione (32 MB) e di tempo, redirect ricontrollati. Un feed fallito mantiene i dati precedenti e registra il codice di errore (`NVD_UNAVAILABLE`, `KEV_INVALID`, …); stato di ogni feed in `GET /api/v1/platform/vulnerabilities`; audit della richiesta e dell'esito.
- I documenti malformati sono rifiutati per intero; i record malformati sono saltati; testi troncati ai limiti delle colonne e ripuliti dai caratteri di controllo.

## 3. Matching conservativo
1. **Dizionario curato** (`resources/vulnintel/cpe-dictionary.json`, versione `2026.11-1`): dal prodotto dichiarato da un servizio (es. `OpenSSH` su `ssh`) al CPE `vendor:product` NVD. Il nome deve corrispondere **per intero** e per quel servizio: niente fuzzy. `Apache-Coyote` non è `apache:http_server`, `nginx-proxy` non è `nginx`; un produttore da solo non produce **mai** un match.
2. Per ogni voce, l'affidabilità della versione: `HIGH` per i banner di protocollo (SSH), `MEDIUM` per l'header `Server` HTTP/RTSP (facile da cambiare).
3. Qualità del match per ogni criterio CPE:
   - versione `-` (non applicabile) → nessun match;
   - versione esatta (anche con il campo *update*, es. `7.2` + `p1` = `7.2p1`; `9.6p1` è della release `9.6`, `9.61` no) → `EXACT_VERSION`;
   - versione `*` con limiti → `VERSION_RANGE` solo se la nostra versione è nel range;
   - versione `*` senza limiti, oppure versione del servizio sconosciuta/non confrontabile → `PRODUCT_ONLY`.
4. Configurazioni NVD con nodi negati ("vulnerabile tranne…") ignorate; configurazioni AND (vulnerabile solo insieme a un altro componente, es. un certo sistema operativo) marcate `requiresPlatform`.
5. Tipo del finding:
   - `CONFIRMED_VULNERABILITY` solo con versione `HIGH`, servizio **confermato**, match esatto o nel range, nessuna condizione di piattaforma;
   - altrimenti `POTENTIAL_RISK` (affidabilità `LOW` se serve un altro componente);
   - `PRODUCT_ONLY` → un solo finding aggregato `cve.product-only` per servizio ("N vulnerabilità note, verifica la versione"), mai "confermato".
6. Gravità dalla CVSS (`NONE` → informativa, assente → bassa), **un livello in più se la CVE è in KEV** (max CRITICAL). Massimo 100 finding CVE per servizio.

## 4. Regole
Classi Java piccole, una per regola, con id e versione (`findings/FindingRules`, tutte versione 1). Leggono solo i dati della scansione.

| Regola | Gravità | Tipo | Quando |
|---|---|---|---|
| `telnet.open` | HIGH | SUSPICIOUS_CONFIGURATION | servizio `telnet` (23, 2323, …) |
| `ftp.cleartext` | MEDIUM | SUSPICIOUS_CONFIGURATION | `ftp` senza TLS |
| `http.login-cleartext` | MEDIUM | SUSPICIOUS_CONFIGURATION | pagina di login o autenticazione Basic/Digest su HTTP senza TLS e senza redirect a HTTPS |
| `tls.legacy-protocol` | LOW (MEDIUM se solo TLS ≤ 1.1) | SUSPICIOUS_CONFIGURATION | TLS 1.0/1.1 accettati |
| `tls.certificate-expired` | LOW | SUSPICIOUS_CONFIGURATION | certificato scaduto |
| `smb.v1-enabled` | HIGH | SUSPICIOUS_CONFIGURATION | SMB1 accettato |
| `upnp.exposed-mapping` | HIGH (CRITICAL con CVE KEV sul dispositivo) | POTENTIAL_RISK | mappatura UPnP del router verso una porta sensibile del dispositivo (o qualsiasi porta di una telecamera) |
| `upnp.igd-enabled` | LOW | POTENTIAL_RISK | il router accetta mappature UPnP |
| `tr069.exposed` | INFORMATIONAL | UNVERIFIED_INFORMATION | TCP 7547 aperta |
| `rtsp.open` | LOW | POTENTIAL_RISK | servizio RTSP |
| `mqtt.cleartext` | MEDIUM | POTENTIAL_RISK | MQTT su 1883 senza TLS |
| `snmp.enabled` | LOW | POTENTIAL_RISK | SNMP UDP risponde (nessuna community mai provata) |
| `dns.open-resolver` | LOW | POTENTIAL_RISK | DNS con ricorsione su un dispositivo che non è il router |
| `device.unknown` | INFORMATIONAL | UNVERIFIED_INFORMATION | dispositivo non identificato senza categoria manuale |
| `cve.version-match` | da CVSS (+1 KEV) | CONFIRMED_VULNERABILITY / POTENTIAL_RISK | §3 |
| `cve.product-only` | LOW (MEDIUM con KEV) | POTENTIAL_RISK | §3 |

Differenze dal catalogo di docs/09 in ADR-056 (SNMP, UPnP IGD, DNS, firmware, "nuovo dispositivo").

## 5. Ciclo di vita, deduplicazione, triage
- `fingerprint = sha256(device, regola, protocollo, porta, CVE, chiave)`: un finding per problema. Se esiste già viene aggiornato (`last_detected_at`, gravità, parametri) e riceve l'evidenza della nuova scansione; un finding `RESOLVED` rilevato di nuovo torna `OPEN`; gli stati di triage vengono mantenuti.
- Un finding attivo (`OPEN`, `ACKNOWLEDGED`) non più rilevato diventa `RESOLVED` **solo se la scansione lo copriva** (ADR-057):
  - porta: il riepilogo `PORTSCAN` del dispositivo non è in pausa, ha la stessa versione della lista porte del backend e il profilo della scansione, e la porta è nella lista di quel profilo (es. una scansione QUICK non risolve Telnet su 2323, che solo STANDARD controlla);
  - UPnP: i dati del router sono stati letti (`controlRefused` → nessuna conclusione);
  - dispositivo: il dispositivo è stato visto.
  Una scansione DISCOVERY non risolve mai i finding di porta.
- Triage manuale (`PATCH /api/v1/findings/{id}/status`, permesso `finding:triage`): `ACKNOWLEDGED`, `FALSE_POSITIVE`, `ACCEPTED_RISK` con **motivazione obbligatoria** (max 500), `OPEN` per riaprire; `RESOLVED` lo imposta solo una scansione (`409 FINDING_RESOLVED` su un finding risolto). Ogni cambio è in audit (`FINDING_STATUS_CHANGED`).
- Evidenze: una per scansione (dati del servizio, qualità del match, CPE, versione del dizionario), max 4000 byte; le CVE collegate in `device_vulnerabilities`.

## 6. API
| Metodo | Percorso | Permesso |
|---|---|---|
| GET | `/api/v1/homes/{homeId}/findings?status&severity&type` | `finding:read` sull'abitazione (max 500, prima gli attivi, poi per gravità) |
| GET | `/api/v1/findings/{id}` | `finding:read`: finding, evidenze (ultime 20), CVE collegate (max 50) con KEV/EPSS |
| PATCH | `/api/v1/findings/{id}/status` | `finding:triage` |
| GET | `/api/v1/vulnerabilities/{cveId}` | `finding:read` |
| GET / POST | `/api/v1/platform/vulnerabilities` / `…/sync` | amministratore di piattaforma |

Titoli, descrizioni e raccomandazioni sono **chiavi i18n con parametri** (`findings.rule.<id>.title|description|recommendation`): il backend non invia testo libero da mostrare. Ruoli: `CUSTOMER`, `TECHNICIAN`, `ORGANIZATION_ADMIN`, `SUPER_ADMIN` leggono e gestiscono; `READ_ONLY` legge.

## 7. Dashboard
Pagina "Problemi di sicurezza" dell'abitazione (link dal dettaglio abitazione): elenco con gravità, tipo, dispositivo/porta, stato; filtri per stato, gravità e tipo; dettaglio con spiegazione del tipo, "Cosa significa", "Cosa fare", CVE (qualità del match, KEV, EPSS, descrizione NVD in inglese), evidenze, gestione con motivazione. Testi IT/EN.

## 8. Limiti
- Il dizionario CPE copre 11 prodotti comuni negli apparati domestici (SSH e server web embedded): i prodotti non in elenco non generano CVE (preferito a un falso positivo). Da estendere con dati reali (M18).
- Le versioni dichiarate dai servizi non sono verificate: per questo l'header HTTP non porta mai a "confermata".
- Nessuna rianalisi delle scansioni passate, nessuna regola "firmware non aggiornato" (manca una fonte affidabile dell'ultima versione). Gli alert "nuovo problema" e "problema risolto" sono stati aggiunti nella M13 ([22-ALERTS-REPORTS.md](22-ALERTS-REPORTS.md)).
- Prova con feed reali e dispositivi reali rimandata: i test usano solo dati [MOCK] (CVE `CVE-2099-*`, server HTTP su loopback).

## 9. Test
- `VulnerabilityMatchingTest`: versioni, dizionario (nomi interi, mai produttore da solo, servizio sbagliato), qualità del match (esatta con update, range, `*`, `-`, versione ignota), parser NVD (negate, AND, prodotti estranei, Primary, riferimenti non http esclusi), KEV/EPSS malformati.
- `FindingRulesTest`: ogni regola con casi positivi e negativi (TLS, redirect HTTPS, resolver del router, categoria manuale, mappature non sensibili), liste porte del backend identiche a quelle dell'agent.
- `SecurityAnalysisTest`: scansione STANDARD → CVE confermata (banner + KEV → CRITICAL), CVE con piattaforma → rischio potenziale, range nginx → rischio potenziale, nessuna CVE per `Apache-Coyote`; QUICK senza Telnet → 23 risolta, 2323 resta aperta; triage con motivazione, falso positivo mantenuto, 409 su risolto; riapertura; altro tenant → 404.
- `VulnerabilitySyncTest`: paginazione NVD, KEV, EPSS da server [MOCK] su loopback, mirror sostituito, feed fallito che mantiene i dati, sorgente HTTP non loopback rifiutata, 403 per non amministratori, 409 se già in corso.
