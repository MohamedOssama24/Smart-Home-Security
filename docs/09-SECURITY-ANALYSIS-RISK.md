# 09 — Security Analysis Engine, Vulnerability Intelligence, Risk Engine

## 1. Security Analysis Engine (backend)
Input: dispositivi + porte + servizi + protocolli + evidenze locali dell'agent. Output: `findings` con evidenze. Il motore è un insieme di **regole versionate** (classi Java piccole, una per regola, con test dedicato) eseguite dopo il fingerprinting. Ri-eseguibile su una scansione passata (`analysis_version`).

### 1.1 Tipologie (sempre distinte nella UI e nei report)
| `finding_type` | Significato | Esempio |
|---|---|---|
| `CONFIRMED_VULNERABILITY` | CVE applicabile con prodotto **e** versione identificati con confidenza HIGH e versione nel range vulnerabile | firmware X 1.2.3 identificato da banner, CVE con range ≤ 1.2.4 |
| `POTENTIAL_RISK` | rischio plausibile ma non verificato fino in fondo | CVE di quel modello, versione non determinabile |
| `SUSPICIOUS_CONFIGURATION` | configurazione osservabile debole | Telnet aperto, pannello admin in HTTP, SMBv1 |
| `UNVERIFIED_INFORMATION` | informazione da verificare, nessun rischio dimostrato | dispositivo non identificato con servizi sconosciuti |

### 1.2 Catalogo regole iniziale
| Regola | Severity | Tipo |
|---|---|---|
| Telnet in ascolto (23/2323) | HIGH | SUSPICIOUS_CONFIGURATION |
| FTP in chiaro | MEDIUM | SUSPICIOUS_CONFIGURATION |
| Interfaccia di amministrazione/login su HTTP non cifrato | MEDIUM | SUSPICIOUS_CONFIGURATION |
| HTTPS con TLS ≤ 1.0 / cert scaduto | LOW–MEDIUM | SUSPICIOUS_CONFIGURATION |
| SMBv1 supportato | HIGH | SUSPICIOUS_CONFIGURATION |
| **Port mapping UPnP verso Internet** su porte di amministrazione/camera | HIGH (CRITICAL se servizio con CVE KEV) | POTENTIAL_RISK |
| UPnP IGD che permette mappature (attivo sul router) | LOW | SUSPICIOUS_CONFIGURATION |
| TR-069/CWMP 7547 raggiungibile dalla LAN | INFORMATIONAL | UNVERIFIED_INFORMATION |
| RTSP esposto sulla LAN | LOW | POTENTIAL_RISK |
| MQTT 1883 senza TLS | MEDIUM | POTENTIAL_RISK |
| SNMP risponde (v1/v2c con community fornita = default) | MEDIUM | SUSPICIOUS_CONFIGURATION |
| DNS resolver aperto su dispositivo non router | LOW | SUSPICIOUS_CONFIGURATION |
| Firmware/software più vecchio dell'ultima versione nota (se dato disponibile) | MEDIUM | POTENTIAL_RISK |
| Nuovo dispositivo sconosciuto | INFORMATIONAL | UNVERIFIED_INFORMATION |
| CVE con match versione esatto | da CVSS | CONFIRMED_VULNERABILITY |
| CVE presente in CISA KEV | +1 livello, max CRITICAL | come sopra |

Ogni finding: Finding ID, Device ID, titolo, descrizione, severity, evidence, confidence, source (`RULE:<id>@<ver>`, `NVD`, `KEV`), timestamp, recommendation, status. Testi in chiavi i18n IT/EN scritti per utenti non tecnici ("Cosa significa", "Cosa fare").

### 1.3 Ciclo di vita e deduplicazione
`fingerprint = hash(device_id, rule_id, protocol, port, cve?)`. Se già aperto ⇒ aggiorna `last_detected_at`. Se una scansione successiva **che ha coperto quella porta/servizio** non lo rileva più ⇒ `RESOLVED` + alert "Problema risolto". Se la scansione non lo copriva (profilo diverso, host non raggiungibile) ⇒ nessun cambiamento. Triage manuale: `ACKNOWLEDGED`, `FALSE_POSITIVE`, `ACCEPTED_RISK` (motivazione obbligatoria, audit).

## 2. Vulnerability Intelligence
| Fonte | Accesso | Frequenza sync |
|---|---|---|
| NVD CVE API 2.0 | API ufficiale gratuita (API key gratuita per limiti più alti) | incrementale ogni 6 h (`lastModStartDate`) |
| NVD CPE Match | API ufficiale | con le CVE |
| CISA KEV | feed JSON ufficiale | giornaliero |
| FIRST EPSS | CSV/API gratuita | giornaliero (prioritizzazione, opzionale) |
| Advisory produttori | curazione manuale/feed CSAF dove disponibili | roadmap |

Queste sono sincronizzazioni di **dati pubblici**, non scansioni della rete dell'utente.

**Matching** (conservativo):
1. Normalizzazione del prodotto rilevato in candidato CPE (`vendor:product`) tramite dizionario curato + CPE dictionary; nessun match fuzzy automatico sotto soglia.
2. `EXACT_VERSION`/`VERSION_RANGE` solo se versione nota con confidenza ≥ MEDIUM; con confidenza HIGH ⇒ `CONFIRMED_VULNERABILITY`, con MEDIUM ⇒ `POTENTIAL_RISK`.
3. `PRODUCT_ONLY` (versione ignota) ⇒ al massimo `POTENTIAL_RISK` aggregato ("il modello ha N vulnerabilità note, verifica il firmware").
4. **Mai** match sul solo produttore.
5. Fonti e data di sincronizzazione conservate e mostrate.

## 3. Risk Engine — Security Score 0–100 (100 = ottimo)
### 3.1 Calcolo spiegabile
```
deduzione(finding) = base(severity) × fattore_tipo × fattore_confidenza × criticità_dispositivo × esposizione × KEV
base:            CRITICAL 30 · HIGH 15 · MEDIUM 6 · LOW 2 · INFORMATIONAL 0
fattore_tipo:    CONFIRMED 1.0 · POTENTIAL 0.6 · SUSPICIOUS 0.5 · UNVERIFIED 0
confidenza:      HIGH 1.0 · MEDIUM 0.8 · LOW 0.5
criticità:       ROUTER, NAS, IP_CAMERA 1.3 · LAPTOP/DESKTOP 1.1 · altri 1.0
esposizione:     raggiungibile da Internet (UPnP mapping) 1.5 · solo LAN 1.0
KEV:             1.5 se CVE in KEV
deduzione_dispositivo = min(Σ deduzioni del dispositivo, 45)        // un dispositivo non azzera da solo il punteggio…
score_grezzo = max(0, 100 − Σ deduzioni_dispositivo)                 // …ma un CRITICAL esposto lo porta comunque basso
```
Finding `ACCEPTED_RISK`/`FALSE_POSITIVE` esclusi (mostrati a parte). Un dispositivo **non identificato non è penalizzato in quanto tale**: conta solo ciò che espone.

### 3.2 Copertura
```
coverage = 0.40 × (host analizzati / host scoperti)
         + 0.25 × profondità profilo (DISCOVERY 0.2 · QUICK 0.6 · STANDARD 0.85 · DEEP 1.0)
         + 0.20 × tecniche di discovery riuscite (ARP, mDNS, SSDP, ICMP pesate)
         + 0.15 × integrazione router disponibile (1/0)
```
Regole anti-falsa-sicurezza: coverage < 0.6 ⇒ score **limitato a 70** e marcato *provvisorio*; coverage < 0.8 ⇒ il giudizio non può essere "Ottimo". Scansione `DISCOVERY` senza porte ⇒ score non calcolato ("Esegui una scansione QUICK o superiore").

### 3.3 Risk level
`≥ 85 LOW` · `65–84 MEDIUM` · `40–64 HIGH` · `< 40 CRITICAL`.

### 3.4 Output (`risk_snapshots`)
Score, risk level, copertura, flag provvisorio, **breakdown** (ogni deduzione con finding, fattori e contributo), top problemi, dispositivi più rischiosi, delta rispetto alla scansione precedente (con motivi: nuovi finding, risolti, nuovi dispositivi). La UI mostra "Perché questo punteggio?".

I pesi sono in configurazione versionata (`engine_version`) e verranno tarati con dati reali; cambiare i pesi non riscrive gli snapshot storici.
