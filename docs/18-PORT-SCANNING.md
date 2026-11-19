# 18 — Rilevamento porte e servizi (Milestone 9)

Dopo la discovery ([16-NETWORK-DISCOVERY.md](16-NETWORK-DISCOVERY.md)), i profili `QUICK` e `STANDARD` controllano le porte dei dispositivi trovati e identificano i servizi con **sole richieste di lettura**. Il modello di riferimento è [08-PORT-SCANNING-SERVICES.md](08-PORT-SCANNING-SERVICES.md). Questo documento descrive ciò che è implementato e le differenze, motivate in ADR-049…ADR-053.

## 1. Profili e liste di porte
| Profilo | TCP | UDP | Disponibilità |
|---|---|---|---|
| `DISCOVERY` | — | — | solo discovery (M6–M8) |
| `QUICK` | 40 porte | 53, 123, 161, 1900, 3702, 5353 | tutti i piani |
| `STANDARD` | 301 porte (IoT, amministrazione, media, stampa, NAS, domotica) | 53, 123, 137, 161, 1900, 3702, 5353, 5683 | tutti i piani |
| `DEEP`, `CUSTOM` | — | — | **non disponibili** (piani a pagamento, M17): `400 PROFILE_NOT_AVAILABLE` |

- QUICK TCP: 21, 22, 23, 25, 53, 80, 81, 88, 110, 139, 143, 443, 445, 554, 631, 993, 995, 1883, 2000, 3389, 5000, 5001, 5357, 5900, 7547, 8000, 8008, 8009, 8080, 8081, 8443, 8554, 8883, 8888, 9000, 9100, 9999, 10000, 49152, 62078.
- Le liste sono in un file dati versionato dentro l'agent (`agent/go-security-agent/internal/portscan/portlists.json`, versione `2026.11-1`), validato all'avvio: porte ordinate, uniche, 1–65535, al massimo 1100 TCP, e **ogni porta UDP deve avere una probe sicura**. Una porta UDP senza probe non viene mai contattata (ADR-050).
- La versione della lista è registrata nei risultati (osservazione `PORTSCAN`).

## 2. Ambito e host controllati
- Sono controllati **solo** gli host trovati dalla discovery della stessa scansione, escluso il computer dell'agent, gli indirizzi IPv6 link-local, loopback e multicast.
- Prima di ogni host l'agent verifica che l'indirizzo appartenga a una rete **autorizzata** del job firmato e **collegata direttamente** a una sua interfaccia. Altrimenti l'host non viene contattato (`PORT_SCAN_OUT_OF_SCOPE`). Senza funzione di ambito non si scansiona nulla.
- Il backend scarta e registra in audit ogni porta fuori dalle reti autorizzate (`OUT_OF_SCOPE_RESULTS`, come per le osservazioni).

## 3. TCP
- **TCP connect** (nessun SYN raw, nessun privilegio). La connessione viene chiusa subito; ai servizi senza probe non viene inviato alcun byte.
- Stati: handshake → `OPEN` (`syn-ack`); RST/rifiuto → `CLOSED` (`rst`); timeout dopo 1 retry → `FILTERED` (`no-response`, **mai** `CLOSED`); altri errori → `UNKNOWN`.
- Limiti firmati nel job (`limits.ports`) e ricontrollati dall'agent: 300 connessioni/s e concorrenza 256 in totale; **8 connessioni e 50/s per host**; timeout 1,5 s (ammessi 200–5000 ms). Valori oltre i massimi → job rifiutato.
- Dopo 5 errori consecutivi l'host viene messo in pausa: nessun'altra connessione né probe UDP (`PORT_SCAN_HOST_PAUSED`, contatore `paused`).
- Annullamento o tempo massimo: si ferma subito, risultati parziali (`PORT_SCAN_INCOMPLETE`).
- Il timeout adattivo sull'RTT ICMP previsto da docs/08 non è implementato: timeout fisso dal job (ADR-052).

## 4. UDP: solo probe di protocollo
| Porta | Probe | Cosa viene letto |
|---|---|---|
| 53 | query DNS standard (record A di `localhost`) | risposta, ricorsione disponibile |
| 123 | NTP client mode 3 (**mai** monlist/mode 6–7) | stratum, versione |
| 137 | NBSTAT | nome del computer, gruppo di lavoro |
| 161 | **SNMPv3 discovery** non autenticata (RFC 3414), costruita a mano | engine ID, enterprise. **Nessuna community** (`public`/`private` mai inviate) |
| 1900 | M-SEARCH unicast | ST, Server, Location |
| 3702 | WS-Discovery Probe | tipi, XAddrs; ONVIF `GetSystemDateAndTime` (non autenticato per specifica) **solo** verso XAddrs con l'IP del dispositivo stesso |
| 5353 | query mDNS unicast `_services._dns-sd._udp.local` | servizi annunciati |
| 5683 | CoAP `GET /.well-known/core` | risorse |

Stati: risposta → `OPEN`; ICMP port unreachable → `CLOSED`; silenzio dopo 1 retry → `OPEN_FILTERED`.

## 5. Identificazione dei servizi
Per ogni porta aperta: nome del servizio, stato `PROBABLE` (solo il numero di porta, affidabilità bassa) o `CONFIRMED` (il dispositivo ha risposto al protocollo), prodotto e versione **dichiarati dal dispositivo**, evidenza (≤ 512 byte per banner, testo ripulito dai caratteri di controllo) e dati TLS.

| Servizio | Richiesta | Mai |
|---|---|---|
| SSH, Telnet, FTP, SMTP, POP3, IMAP, VNC | lettura passiva del banner (2 s) | nessun byte inviato: niente login, niente `USER anonymous`, nessuna negoziazione Telnet |
| HTTP | `GET /` con `User-Agent: SmartHomeSecurityCheck-Agent/<versione>`, 64 KB, nessun redirect seguito, nessun proxy, connessione solo verso l'IP del dispositivo | nessun altro percorso, nessuna credenziale |
| HTTPS / TLS | handshake per versione (TLS 1.3…1.0): versioni, soggetto, emittente, scadenza, autofirmato, nomi; poi `GET /` come HTTP | nessuna validazione bloccante della catena |
| RTSP | solo `OPTIONS` (stato, autenticazione richiesta, server, metodi) | `DESCRIBE`, `SETUP`, `PLAY`, stream, credenziali |
| SMB | SMB2 `NEGOTIATE` (dialetti 2.0.2–3.0.2) e SMB1 `NEGOTIATE` (supporto SMB1): dialetto, firma abilitata/obbligatoria | `SESSION_SETUP`, sessioni anonime, share |
| IPP | `Get-Printer-Attributes` su `/ipp/print` (poi `/`): modello, nome, firmware | stampa, lavori, operazioni amministrative |
| MQTT (1883/8883) | solo porta aperta (+ TLS su 8883) | `CONNECT`, anonimo o con credenziali (ADR-012) |
| altri | `PROBABLE` dal numero di porta | — |

Il dialetto SMB 3.1.1 non è offerto: richiederebbe i contesti di negoziazione (pre-auth integrity) e non cambia l'esito (firma e SMB1). Vedi ADR-053.

## 6. Dati e aggregazione (backend)
- Migrazione `V009__port_scanning.sql`: profili `QUICK`/`STANDARD`, metodo `PORTSCAN`, tabelle `open_ports`, `detected_services`, `detected_protocols` (tutte con RLS), `scan_result_batches.port_count`.
- **Solo le porte aperte sono salvate**, una riga per scansione `(scan, ip, protocollo, porta)`. Le chiuse e silenziose sono contate per host nell'osservazione `PORTSCAN` (`tcp`/`udp`: probed, open, closed, filtered, openFiltered, unknown; `profile`, `listVersion`, `paused`). Vedi ADR-049.
- Upload: le porte viaggiano nel campo `ports` dei batch dei risultati (≤ 500 per batch, batch separati da quelli delle osservazioni, stessa idempotenza `(scan, batchSeq)`; l'hash include le porte). Validazione: protocollo, porta 1–65535, stato, nome servizio `[a-z0-9-]`, stato/affidabilità, testi senza caratteri di controllo, evidenza e TLS ≤ 3500 byte (`DETAILS_TOO_LARGE`). Porte o `PORTSCAN` in una scansione `DISCOVERY` → `400 PORTS_NOT_EXPECTED`.
- Alla chiusura della scansione il fingerprinting (M8) collega le porte al dispositivo e calcola `detected_protocols`: protocolli della discovery (mDNS, SSDP, UPnP, SNMP, NetBIOS, TR-064 → alta) e dei servizi (confermato → alta, probabile → bassa).

## 7. Nuovi indizi di classificazione
Ruleset `2026.11-2` (60 regole). Nuovi segnali: `port` (`tcp/554`), `service` (servizio confermato, fonte = protocollo), `service.probable`, `http.server`, `http.title`, `rtsp.server`, `ipp.model` (anche candidato per il campo Modello).

| Regola | Categoria | Forza |
|---|---|---|
| `camera.onvif` (ONVIF confermato) | Videocamera IP | forte |
| `camera.rtsp-service`, `camera.http`, `camera.http-title` | Videocamera IP | media |
| `printer.ipp-service` (Get-Printer-Attributes) | Stampante | forte |
| `printer.jetdirect-port` (9100/515) | Stampante | debole |
| `router.http-title`; `router.dns-service` | Router | media; debole |
| `nas.http-title`; `nas.afp-port` | NAS | media; debole |
| `tv.cast-port` (8009), `desktop.rdp-port` (3389), `iot.coap-service` | TV, Desktop, IoT | debole |

Le porte aperte da sole sono indizi deboli: non bastano mai a classificare (ADR-047).

## 8. API
| Metodo | Path | Permesso |
|---|---|---|
| POST | `/api/v1/homes/{homeId}/scans` `{"profile":"DISCOVERY"\|"QUICK"\|"STANDARD"}` | `scan:create` |
| GET | `/api/v1/scans/{scanId}/ports` — porte aperte e servizi della scansione | `scan:read` |
| GET | `/api/v1/devices/{id}` — campo `services`: `scanId`, `scannedAt`, `summary` (contatori), `ports`, `protocols` dell'ultima scansione che ha controllato le porte del dispositivo (`null` se mai) | `device:read` |

Agent: job con `profile` e `limits.ports`; fase di avanzamento `PORTS`; batch con `ports`.

## 9. Dashboard
- Pagina Scansioni: scelta del profilo con descrizione, fase "controllo porte e servizi", profilo nello storico, tabella delle porte aperte nel dettaglio di una scansione QUICK/STANDARD.
- Dettaglio dispositivo: contatori dell'ultimo controllo, porte aperte con servizio (probabile/confermato), prodotto e versione, dettagli (titolo, server, autenticazione richiesta, pagina di accesso, SMB1, firma SMB non obbligatoria, versioni TLS, certificato scaduto/autofirmato) e protocolli rilevati. Prodotto, versione e titoli sono indicati come **dichiarati e non verificati**. Testi IT/EN.
- Le porte non sono vulnerabilità: l'analisi del rischio arriverà con la M10.

## 10. Test
- Agent (`go test ./...`): servizi [MOCK] su loopback per SSH, Telnet, FTP, HTTP, redirect, HTTPS, RTSP, SMB, IPP, MQTT e gli 8 protocolli UDP; **test di policy** che registrano tutto ciò che l'agent invia: nessun byte a Telnet/SSH/FTP/MQTT, RTSP solo `OPTIONS`, SMB solo `NEGOTIATE`, HTTP solo `GET /` e `POST /ipp/print` con lo User-Agent, nessun redirect seguito, SNMPv3 senza community, NTP mode 3, ONVIF mai verso altri host, porta UDP senza probe mai contattata, host fuori ambito mai contattato; timeout → `FILTERED`, pausa dopo 5 errori, rate limit, annullamento; verifica dei limiti del job.
- Backend: `PortScanningTest` (job firmato con limiti, fase `PORTS`, ingestione, scarto fuori ambito, idempotenza, classificazione da ONVIF/RTSP/HTTP, dettaglio dispositivo, validazione) + regressione.
- Frontend: `scans.page.spec`, `devices.page.spec`.

## 11. Limiti
- Prova su dispositivi reali rimandata alla fase di test finale (M18), come per M7–M8: i test usano solo servizi [MOCK] su loopback.
- Nessun timeout adattivo (ADR-052); SMB 3.1.1 non offerto (ADR-053).
- `DEEP` e `CUSTOM` arriveranno con i piani (M17).
- Il profilo `STANDARD` su reti con molti dispositivi silenziosi può avvicinarsi alla durata massima della scansione (15 minuti): i risultati restano parziali con avviso.
