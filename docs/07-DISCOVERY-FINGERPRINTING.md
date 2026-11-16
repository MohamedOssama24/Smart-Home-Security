# 07 — Device Discovery e Device Fingerprinting

## 1. Pipeline di discovery (agent)

```
netif ─► scope guard ─► [ARP ∥ ICMP ∥ mDNS ∥ SSDP ∥ Router/DHCP] ─► merge per MAC/IP ─► NetBIOS + rDNS sui nuovi host ─► elenco host
```
Le tecniche girano in parallelo con budget di tempo; ciascuna produce `Observation{ip, mac?, method, iface, timestamp, raw}`. Nessun host viene dichiarato "offline" perché non risponde a un singolo metodo: `online` = visto da almeno un metodo in questa scansione.

### 1.1 Network Interface Discovery
Da `net.Interfaces()` + API di routing OS: IPv4/IPv6, mask, CIDR, gateway di default, tipo (Ethernet/Wi-Fi da nome/OS API), MTU, flag up/loopback. Esclude o marca come virtuali: loopback, Docker/Hyper-V/VirtualBox/WSL, VPN (tun/tap/wg/utun). Reti guest/VLAN: visibili solo se l'agent è collegato a quella rete o tramite dati del router (informativi, mai scansionati attivamente). Dispositivi isolati (client isolation Wi-Fi) non sono raggiungibili: è un limite dichiarato nella copertura.

### 1.2 ARP
| OS | Implementazione | Permessi |
|---|---|---|
| Linux | `mdlayher/arp` (raw socket) | `CAP_NET_RAW` |
| Windows | `SendARP` + `GetIpNetTable2` (iphlpapi via `golang.org/x/sys/windows`) | nessuno speciale |
| macOS | BPF tramite `gopacket/pcap` (libpcap di sistema) se root; altrimenti lettura tabella ARP (`sysctl` route) dopo uno sweep | root opzionale |

Non si usa Npcap su Windows (licenza redistribuzione commerciale a pagamento). Ritmo: ≤ 100 richieste/s, 2 tentativi. Raccoglie IP, MAC, timestamp, interfaccia, metodo.

### 1.3 ICMP
`golang.org/x/net/icmp` (socket datagram non privilegiato su Linux/macOS dove consentito; raw con CAP_NET_RAW), `IcmpSendEcho` su Windows. 1 echo per host, timeout 1 s, 1 retry. Raccoglie anche il **TTL** (input per OS fingerprinting). Nessuna risposta ≠ offline.

### 1.4 mDNS / DNS-SD
Query `_services._dns-sd._udp.local` PTR, poi PTR/SRV/TXT/A/AAAA per servizio (es. `_googlecast._tcp`, `_airplay._tcp`, `_ipp._tcp`, `_hap._tcp`, `_device-info._tcp` con `model=`). Libreria `miekg/dns`; query **QU (unicast response)** da porta effimera per non conflittare con il responder di sistema su 5353. Durata 3–5 s.

### 1.5 SSDP / UPnP
`M-SEARCH ssdp:all` su 239.255.255.250:1900 (MX=2), unicast di follow-up. Per ogni `LOCATION`: fetch della device description XML **solo se l'host dell'URL coincide con l'IP che ha risposto ed è nella rete autorizzata** (anti-SSRF), timeout 3 s, max 256 KB, parser XML senza entità esterne. Raccoglie friendlyName, manufacturer, modelName, modelNumber, deviceType, serviceType, `SERVER` header. Tutto è **auto-dichiarato** → confidenza al più MEDIUM.

### 1.6 Router Integration (solo con autorizzazione del proprietario)
| Protocollo | Uso | Credenziali |
|---|---|---|
| UPnP IGD | IP esterno, **mappature porte attive** (`GetGenericPortMappingEntry`) → esposizione verso Internet | nessuna (servizio pubblicato) |
| TR-064 (es. FRITZ!Box) | elenco host, hostname, MAC, interfaccia, stato, lease DHCP | inserite dal proprietario |
| SNMP v2c/v3 | ARP/IF tables del router | community/utente forniti dal proprietario (mai `public` tentata) |
| API ufficiali produttore | in base al router | in roadmap |

Le credenziali del router restano **sull'agent** (cifrate in archivio OS); il backend conosce solo che l'integrazione esiste. Nessun tentativo di login non autorizzato.

### 1.7 DHCP
Nell'MVP solo via router integration (TR-064/SNMP). Lo sniffing DHCP passivo richiede pcap e privilegi: rimandato.

### 1.8 Hostname
Fonti, in ordine di affidabilità: Router/DHCP → mDNS → NetBIOS (UDP 137 NBSTAT) → SSDP friendlyName → reverse DNS (resolver del gateway). Tutte le varianti sono conservate con la loro fonte.

### 1.9 IPv6
Nessuno sweep di /64 (impossibile e inutile): discovery via tabella neighbor (NDP), ping multicast `ff02::1`, mDNS AAAA. Port scan IPv6 solo su indirizzi effettivamente osservati.

## 2. Device Fingerprinting (backend, con hint dall'agent)

### 2.1 Correlazione identità
Chiave primaria: `(home, MAC)`. Senza MAC (host fuori L2 noti via router): `(home, IP, hostname)` con confidenza ridotta. **MAC randomizzati** (bit "locally administered") marcati `mac_randomized=true`: niente produttore da OUI; correlazione euristica tramite hostname/mDNS name, mostrata come "probabilmente lo stesso dispositivo".

### 2.2 OUI
Registri IEEE MA-L/MA-M/MA-S (CSV pubblici) in tabella `oui_entries`, aggiornati dal backend (job di sync dati) e distribuiti all'agent come snapshot con ETag. Il risultato è il **produttore della scheda di rete**, che spesso differisce dal marchio del prodotto (es. modulo Wi-Fi Espressif in un prodotto di altra marca): usato come indizio **debole** per manufacturer di prodotto.

### 2.3 Motore di classificazione (regole + punteggi)
Ogni regola: `id`, condizioni sulle evidenze, categoria candidata, peso, forza (`STRONG`/`MODERATE`/`WEAK`). Ruleset versionato (YAML in repo, caricato all'avvio, `ruleset_version` salvato con il risultato).

| Esempio regola | Categoria | Forza |
|---|---|---|
| WS-Discovery ONVIF `NetworkVideoTransmitter` | IP_CAMERA | STRONG |
| RTSP 554 aperto + OUI produttore di telecamere | IP_CAMERA | MODERATE |
| `_ipp._tcp`/`_printer._tcp` o IPP 631 confermato | PRINTER | STRONG |
| SSDP `MediaRenderer` + `_googlecast`/DIAL | SMART_TV (o media device) | MODERATE |
| SMB + `_smb._tcp` + `_adisk._tcp`/UPnP NAS model | NAS | MODERATE |
| `_hap._tcp`/MQTT 1883 + OUI Espressif/Tuya | SMART_PLUG / IOT | WEAK→MODERATE combinati |
| default gateway + UPnP IGD | ROUTER | STRONG |
| `_device-info._tcp model=iPhone…` | SMARTPHONE | STRONG |
| solo OUI | — | WEAK |

Decisione: categoria scelta se `punteggio ≥ soglia` **e** (≥ 1 evidenza STRONG **oppure** ≥ 2 evidenze MODERATE da fonti indipendenti). Un singolo indizio debole non basta mai. Altrimenti `UNKNOWN_DEVICE`. Categorie: ROUTER, IP_CAMERA, SMART_TV, SMARTPHONE, TABLET, LAPTOP, DESKTOP, PRINTER, NAS, SMART_PLUG, SMART_SPEAKER, IOT, UNKNOWN_DEVICE.

### 2.4 Classificazione manuale
`manual_category` prevale nella UI ma `detected_category` resta calcolata e visibile; ogni modifica salva vecchia/nuova categoria, fonte, utente, data (`device_category_changes`). Se una scansione successiva rileva evidenze STRONG contrastanti, viene mostrato un suggerimento (mai sovrascrittura automatica).

## 3. Confidenza (globale e per campo)
Affidabilità delle fonti per campo (tabella configurabile):

| Fonte | IP | MAC | Manufacturer | Hostname | Type | Model | OS | Firmware |
|---|---|---|---|---|---|---|---|---|
| ARP | H | H | — | — | — | — | — | — |
| Router/DHCP | H | H | — | H | L | — | — | — |
| mDNS device-info | M | — | M | M | M | M | M | — |
| SSDP description | M | — | M | L | M | M | — | L |
| Banner servizio (versione esplicita) | — | — | M | — | M | M | M | M |
| OUI | — | — | L | — | L | — | — | — |
| TTL / euristiche | — | — | — | — | — | — | L | — |

Regola di aggregazione per campo: **HIGH** = ≥ 2 fonti indipendenti concordi di cui almeno una H, oppure fonte H autoritativa per quel campo (es. IP/MAC da ARP); **MEDIUM** = una fonte M o due fonti L concordi; **LOW** = una sola fonte debole; fonti in conflitto ⇒ si abbassa di un livello e si registra il conflitto. Campo senza fonti ⇒ **valore nullo** ("Non determinato"): nessuna informazione inventata.
Confidenza globale del dispositivo = funzione di quella di `DEVICE_TYPE` e `MANUFACTURER` (HIGH richiede conferma da router o protocollo specifico).

## 4. OS fingerprinting (opzionale, profilo DEEP)
Indizi: TTL iniziale stimato (64 Linux/macOS/iOS/Android, 128 Windows, 255 embedded/network), SMB negotiate, banner SSH/HTTP, mDNS/SSDP, router. TCP window/options solo in modalità privilegiata Linux/macOS. Esiti: Windows, Linux, macOS, Android, iOS, Embedded Linux, Unknown, sempre con confidenza; **il solo TTL dà al massimo LOW**.
