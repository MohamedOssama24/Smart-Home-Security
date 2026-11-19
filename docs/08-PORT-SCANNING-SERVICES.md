# 08 — Port Scanning, Service & Protocol Detection

> **Implementazione (M9)**: vedi [18-PORT-SCANNING.md](18-PORT-SCANNING.md). Differenze: solo le porte aperte sono salvate (le altre come contatori, ADR-049), liste nell'agent (ADR-050), `DEEP`/`CUSTOM` rimandati alla M17 (ADR-051), timeout fisso (ADR-052), SMB senza 3.1.1 (ADR-053), test MQTT anonimo non implementato (ADR-012).

## 1. TCP scanner
- Tecnica: **TCP connect** (`net.Dialer{Timeout}` con `DialContext`), nessun raw SYN scan (niente pcap/privilegi, comportamento più gentile verso i dispositivi).
- Stati:

| Esito della connect | Stato | Motivo registrato |
|---|---|---|
| handshake completato | `OPEN` | `syn-ack` |
| `ECONNREFUSED` / `WSAECONNREFUSED` (RST) | `CLOSED` | `rst` |
| timeout (anche dopo retry) | `FILTERED` | `no-response` — **mai CLOSED** |
| host/net unreachable, altri errori | `UNKNOWN` | errore specifico |

- Le porte `CLOSED` non vengono salvate singolarmente (solo contatori), le altre sì.
- Controlli di carico (configurabili dal job): concorrenza globale 256, **per host 8**, token bucket globale 300 conn/s, per host 50 conn/s, timeout 1,5 s (adattivo su RTT ICMP), 1 retry per i timeout, chiusura immediata della connessione. Pausa automatica su un host che produce errori ripetuti.
- Liste porte: `QUICK` (~40: 21,22,23,53,80,81,443,445,554,631,1883,5000,7547,8000,8080,8443,8883,9000,49152…), `STANDARD` (~300 porte IoT/admin/media), `DEEP` (1–1024 + porte note >1024), `CUSTOM` (range validati, piano superiore). Liste versionate in un file dati, non nel codice.

## 2. UDP — modulo separato, solo probe protocollo-specifiche
| Porta | Probe | Note |
|---|---|---|
| 53 | query DNS standard (record A di un nome locale) | rileva resolver aperti |
| 1900 | M-SEARCH unicast | |
| 5353 | query mDNS unicast | |
| 161 | **SNMPv3 discovery** (richiesta engine ID non autenticata, RFC 3414) | nessuna community tentata; v2c solo con community fornita dal proprietario |
| 5683 | CoAP `GET /.well-known/core` | IoT |
| 137 | NBSTAT | |
| 3702 | WS-Discovery Probe (ONVIF) | |
| 123 | richiesta NTP client mode 3 | **mai** comandi monlist |

Stati UDP: risposta ⇒ `OPEN`; ICMP port unreachable (errore sul socket connesso) ⇒ `CLOSED`; nessuna risposta ⇒ `OPEN_FILTERED` (mai `CLOSED` senza evidenza). MQTT è TCP (1883/8883), gestito dal TCP scanner.

## 3. Service detection
Distinzione esplicita, salvata per ogni porta:
- **Porta aperta** (fatto);
- **Servizio probabile** (`PROBABLE`): dedotto dal numero di porta → confidenza LOW;
- **Servizio confermato** (`CONFIRMED`): handshake/banner del protocollo riconosciuto;
- **Versione**, **evidenza** (estratto banner troncato a 512 byte, header), **confidenza**.

| Servizio | Probe sicura |
|---|---|
| SSH, FTP, SMTP, Telnet | lettura passiva del banner (≤ 2 s). Telnet: solo banner, nessuna negoziazione/login. FTP: niente `USER anonymous` |
| HTTP | `GET /` con `User-Agent: SmartHomeSecurityCheck-Agent/<ver>`, nessun redirect off-host, max 64 KB; header `Server`, `<title>`, presenza form di login, redirect a HTTPS |
| HTTPS/TLS | handshake: versioni supportate, cert subject/issuer, scadenza, self-signed, nome; nessuna validazione catena "bloccante" |
| RTSP | `OPTIONS` soltanto (nessun `DESCRIBE`/`PLAY`, nessuno stream) |
| ONVIF | WS-Discovery + `GetSystemDateAndTime` (non autenticato per specifica); nessuna chiamata autenticata |
| SMB | SMB2 `NEGOTIATE` (dialetti, SMB1 supportato?, signing); **nessun** session setup |
| MQTT | solo rilevazione porta + TLS su 8883; il test "accesso anonimo" (CONNECT senza credenziali) è **disabilitato** e richiede decisione (vedi ADR-012) |
| UPnP/SSDP, mDNS, SNMP, DNS | vedi UDP/discovery |
| IPP | `Get-Printer-Attributes` (operazione pubblica) |

Regole generali: nessun exploit, payload distruttivi, brute force, credenziali predefinite o login anonimi; ogni probe ha timeout e limite di byte; tutti i dati ricevuti sono trattati come input non fidato.

## 4. Protocol detection
Aggregazione per dispositivo dei protocolli osservati (mDNS, SSDP/UPnP, ONVIF, RTSP, MQTT, SMB, SNMP, CoAP, DNS, HTTP/S, Telnet, FTP, SSH) con dettagli e confidenza → `detected_protocols`, input del classificatore e dell'analisi.
