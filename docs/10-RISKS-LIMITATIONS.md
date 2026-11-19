# 10 — Rischi e limitazioni tecniche

## Limitazioni intrinseche (da comunicare chiaramente all'utente e nei report)
| # | Limitazione | Impatto | Mitigazione |
|---|---|---|---|
| L1 | L'agent vede solo le sottoreti a cui è collegato | VLAN/guest/IoT separate non analizzate | dati router (informativi); più agent per home; Raspberry Pi gateway futuro |
| L2 | Client isolation Wi-Fi / AP isolation | dispositivi invisibili | segnalato in copertura |
| L3 | MAC randomizzati (iOS/Android/Windows) | identità instabile, niente produttore | correlazione per hostname/mDNS, flag "privato" |
| L4 | Dispositivi in standby / Wi-Fi power save | non rispondono in quel momento | più tecniche + "ultimo visto"; mai "offline" da un solo metodo |
| L5 | Zigbee / Z-Wave / BLE / Thread | non sono dispositivi IP | solo via gateway: inventario Home Assistant (M15, [24-INTEGRATIONS.md](24-INTEGRATIONS.md)), dichiarato e non verificato |
| L6 | Firmware e modello spesso non esposti | match CVE limitato | finding "potenziali", mai confermati senza versione |
| L7 | Informazioni auto-dichiarate (SSDP, banner) falsificabili | errori di identificazione | confidenza ≤ MEDIUM, conflitti registrati |
| L8 | TCP connect scan non distingue alcuni firewall | FILTERED ambiguo | stato esplicito, mai CLOSED da timeout |
| L9 | Windows senza driver di cattura | niente ARP raw/TCP options | API iphlpapi (sufficienti per ARP/ICMP); OS fingerprint ridotto |
| L10 | Esposizione Internet reale non verificabile dall'interno | sappiamo delle mappature UPnP, non di port forward manuali | roadmap: "external check" dal cloud verso l'IP pubblico **solo previo consenso esplicito e verifica di titolarità** |
| L11 | NVD: arretrati di analisi/CPE incompleti | CVE non associate | KEV + advisory produttori; finding prudenti |

## Rischi di progetto
| # | Rischio | Prob. | Impatto | Mitigazione |
|---|---|---|---|---|
| R1 | Cartella progetto dentro repo git `lavoro` (remote `webmedica/terapANGULAR`) con file sensibili non tracciati | Alta | **Alto** (commit/push accidentali nel repo aziendale) | `git init` dedicato prima di ogni commit (ADR-001) |
| R2 | Toolchain locale incompleta (Go/Flutter assenti, `JAVA_HOME` rotto, Node 18 EOL) | Certa | Medio | setup in Milestone 2 |
| R3 | Uso improprio dello strumento come scanner offensivo | Media | Alto (legale/reputazionale) | reti autorizzate con attestazione, solo IP privati, profili non offensivi, audit, ToS |
| R4 | Agent compromesso / falso agent che invia dati | Media | Medio | chiavi per-agent, revoca, validazione scope, rate limit, nessun comando dal cloud oltre ai job firmati |
| R5 | Backend compromesso usato per comandare gli agent | Bassa | Alto | job firmati, agent limita comunque ai CIDR locali privati, nessuna esecuzione di codice arbitrario, update firmati con chiave offline |
| R6 | Falsi positivi che spaventano utenti non tecnici | Alta | Medio | tassonomia confermato/potenziale, linguaggio chiaro, triage |
| R7 | Dispositivi IoT fragili che si bloccano sotto scansione | Media | Medio | rate limit per host bassi, profili progressivi, kill-switch per tipo dispositivo |
| R8 | Firma codice agent (Windows SmartScreen, macOS notarization) | Alta | Medio | certificato code signing (~€200–400/anno) + Apple Developer (€99/anno): **costo da approvare** |
| R9 | Antivirus/EDR segnalano lo scanner | Media | Medio | binario firmato, comportamento conservativo, documentazione |
| R10 | GDPR (IP/MAC/hostname dati personali; B2B tratta dati di terzi) | Certa | Alto | hosting UE, DPA, retention, export/cancellazione |
| R11 | Ampiezza del perimetro (18 milestone) | Alta | Alto | MVP rigoroso, milestone incrementali con test |
| R12 | Licenze: Npcap (pagamento per redistribuzione), librerie GPL nell'agent | Media | Medio | niente Npcap, preferenza MIT/BSD/Apache per l'agent, verifica licenze in CI |
