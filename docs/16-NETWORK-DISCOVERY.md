# 16 — Network Discovery (Milestone 7)

Discovery completa dei dispositivi presenti sulle reti autorizzate di un'abitazione. Estende la discovery minima della M6 (interfacce + ARP, [15-MANUAL-SCANS.md](15-MANUAL-SCANS.md)); il profilo del job resta `DISCOVERY` e parte solo da un'azione esplicita nella dashboard. Correlazione in inventario, OUI e classificazione sono della M8.

## 1. Ambito (regola invariata)
- **Obiettivi**: solo le reti autorizzate dell'abitazione, firmate nel job. L'agent sonda attivamente (ARP, ICMP, NetBIOS) solo gli indirizzi di un obiettivo **collegato direttamente** a una sua interfaccia; un obiettivo non collegato è saltato (`TARGET_NOT_CONNECTED`), mai instradato.
- **Multicast** (mDNS, SSDP, echo IPv6 `ff02::1`): inviato solo sull'interfaccia di una rete autorizzata collegata, TTL/hop-limit di link (mDNS 255 come da RFC, non instradabile per 224.0.0.251; SSDP TTL 2; IPv6 hop-limit 1).
- **Ogni risposta** è tenuta solo se il suo indirizzo appartiene a un obiettivo autorizzato (collector dell'agent); il backend ricontrolla ogni IP (ADR-040) e scarta il resto in audit.
- Nessuna scansione di porte, nessuna credenziale provata, nessun accesso ai dispositivi oltre ai messaggi di discovery e alle descrizioni che i dispositivi stessi annunciano.

## 2. Pipeline dell'agent
```
interfacce → piano (ambito) → [ARP ∥ ICMP ∥ mDNS ∥ SSDP/UPnP+IGD ∥ IPv6 NDP ∥ router] → NetBIOS + rDNS sui trovati → merge per (IP, metodo)
```
ARP e ICMP si dividono il rate del job (metà ciascuno); il progresso è `2 × host` (ARP + ICMP). Dettagli per osservazione ≤ 3000 byte (oltre: `{"truncated":true}`).

| Metodo | Come | Piattaforme | Limiti dichiarati |
|---|---|---|---|
| `ICMP` | 1 echo per host + 1 ritentativo; TTL della risposta | Windows `IcmpSendEcho2Ex` (senza privilegi); Linux/macOS socket ICMP datagram, altrimenti raw | nessuna risposta ≠ spento (firewall) |
| `MDNS` | DNS-SD: `_services._dns-sd._udp` poi istanze (max 24 tipi), richiesta risposta unicast (QU) da porta effimera | tutte | le risposte inviate solo in multicast non sono viste; TXT: solo chiavi modello/nome/produttore |
| `SSDP` | `M-SEARCH ssdp:all` (×2), finestra 3 s; descrizione UPnP del dispositivo | tutte | max 64 dispositivi |
| `UPNP_IGD` | sul gateway: `GetExternalIPAddress`, `GetGenericPortMappingEntry` (max 32) | tutte | dati autodichiarati |
| `NETBIOS` | NBSTAT unicast UDP 137 ai soli host trovati (max 256) | tutte | solo host con NetBIOS attivo |
| `RDNS` | PTR tramite il resolver del sistema (max 256, 8 in parallelo) | tutte | dipende dal DNS locale |
| `NDP` | echo a `ff02::1` + tabella dei vicini IPv6 | Linux (echo + netlink), macOS (echo), Windows (solo tabella `GetIpNetTable2`, `NDP_TABLE_ONLY`) | una /64 non è mai scansionata |
| `TR064` | tabella host del router (`Hosts:1`), digest HTTP | tutte | solo se configurato dal proprietario |
| `SNMP` | `sysName`, `sysDescr`, `ipNetToMediaPhysAddress` (max 1024) v2c/v3 | tutte | solo se configurato; v2c senza cifratura |

## 3. Anti-SSRF (SSDP, UPnP, TR-064)
Gli URL annunciati da un dispositivo (`LOCATION`, `controlURL`, `URLBase`) sono seguiti solo se: schema `http`, nessuna user-info, host = **IP letterale uguale al dispositivo che li ha annunciati** (nessuna risoluzione di nomi), dispositivo nell'ambito. Il client HTTP non usa proxy, non segue redirect, il dialer può raggiungere solo quell'indirizzo, timeout 3 s, risposta ≤ 256 KB, XML con `encoding/xml` (nessuna entità esterna). Un URL rifiutato è segnalato (`descriptionRefused` / `controlRefused`) e mai seguito.

## 4. Integrazioni router (credenziali del proprietario)
- Configurate **solo sull'agent**: `shsc-agent router set-tr064|set-snmp|show|remove`. I segreti sono letti da stdin, mai stampati, salvati in `router.json` protetto come la chiave (DPAPI su Windows, 0600 altrove) e cancellati da `Retire`.
- Il backend riceve solo i nomi (`capabilities.routerIntegrations`: `TR064`, `SNMP`).
- Rifiutate le community predefinite (`public`, `private`); SNMPv3 con privacy richiede autenticazione.
- L'indirizzo del router deve appartenere alle reti autorizzate del job (`ROUTER_OUT_OF_SCOPE` altrimenti: nessun pacchetto).
- Un rifiuto delle credenziali interrompe subito l'integrazione (`ROUTER_AUTH_FAILED`): un solo tentativo, nessun retry, nessuna variante.
- TR-064 su HTTP 49000 con digest (la password non viaggia in chiaro); HTTPS 49443 non usato (certificato self-signed del router).

## 5. Backend e dati
- `V007__network_discovery.sql`: nuovi metodi nel CHECK di `scan_observations`, colonne `hostname` (1–255) e `details` (oggetto JSON ≤ 4096 byte).
- Upload: `hostname` senza caratteri di controllo, `details` ≤ 3500 byte serializzati (400 `DETAILS_TOO_LARGE`), metodo in elenco chiuso; un lotto non valido è rifiutato per intero.
- `GET /api/v1/scans/{id}/devices`: indirizzi raggruppati per MAC (IPv4 + IPv6 della stessa interfaccia; è un'indicazione, non un inventario), `hostname` scelto per affidabilità `TR064 > MDNS > NETBIOS > SNMP > RDNS`, `hostnames` deduplicati, `evidence` per metodo con i dettagli. I dati dichiarati dal dispositivo hanno `selfDeclared: true` e la dashboard li mostra come "non verificati".

## 6. Avvisi
`ICMP_UNAVAILABLE`, `MDNS_UNAVAILABLE`, `SSDP_UNAVAILABLE`, `NETBIOS_UNAVAILABLE`, `NDP_TABLE_ONLY`, `NDP_UNAVAILABLE`, `ROUTER_OUT_OF_SCOPE`, `ROUTER_AUTH_FAILED`, `ROUTER_UNREACHABLE` (oltre a quelli della M6). Ogni avviso porta la scansione a `COMPLETED_WITH_WARNINGS`. `IPV6_NOT_SUPPORTED` non è più emesso (resta tradotto per le scansioni storiche).

## 7. Test
- Agent: responder **[MOCK]** su loopback per mDNS, SSDP + descrizione + IGD, NetBIOS, TR-064 con digest (successo e rifiuto senza retry), router SNMPv2c (sysName/sysDescr + tabella ARP; community errata senza varianti); casi negativi anti-SSRF; parser netlink; pipeline con tecniche finte che restituiscono anche indirizzi fuori ambito. SNMPv3 senza mock.
- Backend: `NetworkDiscoveryTest` (validazione, IPv6, raggruppamento, affidabilità nomi, router integrations).
- Dashboard: tabella dispositivi con nomi, indirizzi raggruppati, dati dichiarati e port mapping.
- **Non eseguita**: prova manuale su una LAN reale autorizzata (in questo ambiente l'E2E è consentito solo sulla rete virtuale WSL). Da eseguire dal proprietario sulla propria rete con la procedura del §8.

## 8. Procedura di verifica su LAN reale autorizzata
Solo sulla **propria** rete (o con autorizzazione scritta del proprietario), avvisando chi la usa. Nell'esempio: LAN `192.168.1.0/24`, router `192.168.1.1`, agent sul PC `192.168.1.50`. Sostituire con i propri valori (`ipconfig` / `ip -4 addr`).

**Prerequisiti**
- Stack avviato: `docker compose up -d`.
- Agent eseguito **sul sistema host** (non in un container o in WSL, che vedono solo la rete virtuale). Binario da `agent/go-security-agent/bin/`.
- Facoltativo: Wireshark sul PC dell'agent.

**Passi**
1. **Rete autorizzata.** Dashboard → abitazione → Reti: aggiungere `192.168.1.0/24`, ed eventualmente il prefisso IPv6 ULA della LAN, poi **Autorizza**.
   - Atteso: rete in stato autorizzato.
2. **Enrollment.** Generare il codice di enrollment, salvarlo in `token.txt`, poi:
   ```
   shsc-agent enroll --api https://<host>:<SHSC_HTTPS_PORT> --token-file token.txt --ca-file dev-ca.pem
   ```
   Cancellare subito `token.txt`.
3. **Autodiagnosi:**
   ```
   shsc-agent diagnose
   ```
   - Atteso: l'interfaccia LAN con `192.168.1.50/24`, backend raggiungibile, nessuna integrazione router.
4. **Router (facoltativo, solo con credenziali create da te sul router).** Il segreto si digita su stdin e non appare a video:
   ```
   shsc-agent router set-tr064 --address 192.168.1.1 --username <utente>
   shsc-agent router set-snmp --address 192.168.1.1 --version 3 --username <utente> --auth SHA256 --priv AES
   shsc-agent router show
   ```
   - Atteso: `show` elenca le integrazioni senza segreti.
   - Atteso: con `--version 2c`, la community `public` o `private` viene rifiutata.
5. **Avvio dell'agent:** `shsc-agent run` in primo piano, oppure `shsc-agent service install` da amministratore.
   - Atteso: la pagina dell'abitazione mostra l'agent online e, se configurate, le integrazioni router nella diagnostica.
6. **Scansione.** Avviare Wireshark (facoltativo) con questo filtro, poi Dashboard → Scansioni → **Nuova scansione** (`DISCOVERY`):
   ```
   ip.src == 192.168.1.50 && !(ip.dst == 192.168.1.0/24) && !(ip.dst == 224.0.0.0/4) && !(udp.port == 53) && !(tcp.port == <SHSC_HTTPS_PORT>)
   ```
7. **Risultati attesi**
   - Stato `COMPLETED`, oppure `COMPLETED_WITH_WARNINGS` con avvisi spiegati (es. `NDP_TABLE_ONLY`, `ICMP_UNAVAILABLE`).
   - Il router compare con `ARP` e, se UPnP è attivo, con `SSDP`/`UPNP_IGD` (IP esterno; inoltri di porte marcati "non verificati").
   - I dispositivi noti (telefoni, TV, stampanti) compaiono con almeno un metodo; dove disponibili, nomi da `MDNS`/`NETBIOS`/`TR064`/`SNMP`/`RDNS`.
   - Confrontare il numero di dispositivi con l'elenco dei client del router. Mancano solo i dispositivi spenti o isolati (client isolation, rete ospiti): è un limite dichiarato, non un errore.
   - Wireshark: nessun pacchetto con il filtro sopra durante la scansione.
8. **Controllo dell'ambito nel database.** Atteso: **0 righe** (`<<` = "contenuto in").
   ```
   docker compose exec postgres psql -U shsc_admin -d shsc -c "SELECT ip, method FROM scan_observations WHERE scan_id = '<id scansione>' AND NOT (ip << '192.168.1.0/24' OR ip << '<prefisso IPv6 autorizzato>')"
   ```
9. **Casi negativi**
   - **Router fuori ambito.** `shsc-agent router set-tr064 --address 10.99.99.1 --username x`, poi una nuova scansione.
     - Atteso: avviso `ROUTER_OUT_OF_SCOPE` e nessun pacchetto verso `10.99.99.1` in Wireshark.
   - **Credenziali errate.** Configurare una password volutamente errata, poi una nuova scansione.
     - Atteso: `ROUTER_AUTH_FAILED` per TR-064/SNMPv3, `ROUTER_UNREACHABLE` per SNMPv2c (che non risponde a una community errata).
     - Atteso nel log del router: **un solo** tentativo di accesso.
10. **Pulizia:** `shsc-agent router remove`; se non serve più, `shsc-agent service uninstall` e revoca dell'agent dalla dashboard.
