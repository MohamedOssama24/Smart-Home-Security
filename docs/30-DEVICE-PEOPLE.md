# 30 — Dispositivo ↔ persona (Milestone 24)

Associa i dispositivi dell'abitazione alle persone che li usano. Decisioni in ADR-081; obiettivi e criteri in [29-ROADMAP-M19-M23.md](29-ROADMAP-M19-M23.md) §M24.

## 1. Stato
| Parte | Contenuto | Stato |
|---|---|---|
| 1 | Persone, associazioni manuali, associazioni automatiche dai nomi dei dispositivi e di Home Assistant | Implementata |
| 2 | Active Directory: accessi al dominio (IP → account), ADR-083 | Implementata, testata solo con dati MOCK |
| 3 | Firewall Sophos: syslog delle autenticazioni (IP → utente), ADR-083 | Implementata, testata solo con dati MOCK |

## 2. Dati
- `home_people`: nome (1–100 caratteri, unico per abitazione senza distinzione maiuscole/minuscole), origine (`USER`, `DEVICE_NAME`, `HOME_ASSISTANT`, `DIRECTORY`, `FIREWALL`), `dismissed`.
- `device_person_assignments`: dispositivo, persona, stato (`PROBABLE`, `CONFIRMED`, `REJECTED`), fonte, evidenza (il nome da cui viene l'associazione).
- RLS per tenant su entrambe. Nessuna posizione, nessun orario di presenza, nessun dato di traffico.

## 3. Associazioni automatiche
- A fine scansione, nella stessa transazione, senza traffico.
- Nomi esaminati: nome attuale del dispositivo, tutte le fonti del campo `HOSTNAME` (mDNS, NetBIOS, router/DHCP…), nome dato dall'utente, nome del dispositivo in Home Assistant.
- Forme riconosciute:
  - "dispositivo di/of Nome [Cognome]": `iPhone-di-Marco`, `Galaxy-S21-di-Giulia`, `MacBook-Pro-di-Luca-Rossi`;
  - "Nome[s]-dispositivo": `Marcos-iPhone` (Apple scrive così "Marco's iPhone"), `Luca-PC`.
- Serve una parola di dispositivo (iPhone, Galaxy, PC, laptop…). Parole generiche e nomi predefiniti non danno persone: `DESKTOP-AB12CD3`, `Android_3`, `Admin-PC`, `Sala-PC`, `iPad-di-casa`.
- Risultato: persona creata se manca, associazione `PROBABLE` con fonte ed evidenza.
- Non vengono mai toccate: le associazioni confermate o tolte dall'utente, le persone automatiche eliminate dall'utente.

## 4. API
| Metodo | Percorso | Permesso | Note |
|---|---|---|---|
| GET | `/api/v1/homes/{homeId}/people` | `person:read` | persone visibili con `devices` (`PROBABLE` e `CONFIRMED`) |
| POST | `/api/v1/homes/{homeId}/people` `{name}` | `person:manage` | `201`; `409 PERSON_EXISTS`; `400 INVALID_NAME` |
| PUT | `/api/v1/people/{id}` `{name}` | `person:manage` | rinomina |
| DELETE | `/api/v1/people/{id}` | `person:manage` | `204`; cancella le associazioni |
| PUT | `/api/v1/devices/{deviceId}/people/{personId}` | `person:manage` | associa o conferma (`CONFIRMED`, fonte `USER`) |
| DELETE | `/api/v1/devices/{deviceId}/people/{personId}` | `person:manage` | toglie (`REJECTED`, non riproposta) |

Altri tenant e abitazioni fuori dagli ambiti: `404`; abitazione visibile senza permesso: `403`. Audit: `PERSON_CREATED`, `PERSON_RENAMED`, `PERSON_DELETED`, `DEVICE_PERSON_ASSIGNED`, `DEVICE_PERSON_REMOVED` (senza il nome).

## 5. Interfacce
- Web, pagina Dispositivi: colonna "Persona" (con "probabile"), elenco delle persone dell'abitazione con eliminazione, nel dettaglio la sezione "Persone" con fonte ed evidenza, conferma, rimozione, associazione a una persona esistente o nuova. Avviso privacy.
- App: sezione "Persone" nel dettaglio del dispositivo, in sola lettura.

## 6. Test
- `PersonNamesTest`: forme riconosciute e nomi generici esclusi **[MOCK]**.
- `DevicePeopleTest`: scansione **[MOCK]** via API, associazioni automatiche, conferma, rimozione non riproposta, persona eliminata non ricreata, permessi (`READ_ONLY` 403), isolamento tra tenant, cancellazione delle associazioni.
- Angular `devices.page.spec.ts`, Flutter `dashboard_test.dart`.

## 7. Privacy e limiti
- Sul lavoro, associare dispositivi a dipendenti richiede informativa GDPR e il rispetto dell'art. 4 dello Statuto dei lavoratori (controllo a distanza): la decisione è del titolare.
- Con nomi predefiniti (DESKTOP-xxx, Android_xxx) la parte 1 trova poche persone; un nome può riferirsi a un dispositivo prestato.
- Collegamento della persona a un account SHSC: colonna presente, non ancora esposto dalle API.

## 8. Active Directory e Sophos (parti 2 e 3, ADR-083)
Fonti dell'organizzazione, configurate sull'agent dall'IT. Il backend non contatta mai controller di dominio o firewall.

**Active Directory** (`shsc-agent directory set --server IP-DC --user ACCOUNT [--domain DOMINIO] [--hours 12]`, password da standard input):
- a ogni scansione avviata dalla dashboard l'agent Windows legge, dal registro Security del controller di dominio, gli accessi riusciti `4624` (tipi 2, 3, 7, 10, 11) e le richieste di ticket Kerberos `4768` riuscite delle ultime ore (massimo 72, al più 20.000 eventi);
- usa l'API Windows Event Log (`wevtapi.dll`, sessione RPC remota in sola lettura) con un account creato dall'IT e membro solo di "Event Log Readers";
- vengono ignorati account computer (`…$`), accessi anonimi o di sistema e indirizzi locali;
- il controller di dominio deve stare in una rete autorizzata della scansione; altrimenti non viene contattato (avviso `DIRECTORY_OUT_OF_SCOPE`).

**Sophos** (`shsc-agent sophos set --firewall IP [--listen :5514]`, poi riavvio dell'agent):
- il firewall invia il syslog all'agent (UDP 5514 predefinita); vengono accettati solo i pacchetti dall'indirizzo del firewall;
- dai campi `user_name`/`user` e `src_ip`/`srcip` resta in memoria solo la coppia IP ↔ utente, per 12 ore. Il resto del messaggio viene scartato e mai salvato o registrato;
- l'apertura della porta nel firewall di Windows spetta all'utente o all'IT.

**Flusso**:
- l'agent invia le coppie delle reti autorizzate in un batch separato (`identities`); il backend scarta gli indirizzi fuori rete (audit `SCAN_RESULTS_OUT_OF_SCOPE`) e salva il resto in `scan_identities` (V024), che si cancella insieme alla scansione;
- a fine scansione, l'account visto sull'indirizzo di un dispositivo di quella scansione diventa una persona (`origin` DIRECTORY o FIREWALL, chiave = account in minuscolo) con associazione PROBABILE ed evidenza `account @ IP, ora`;
- lo stesso account da entrambe le fonti, o con lo stesso nome di una persona esistente, riusa quella persona; una persona eliminata dall'utente non viene ricreata.

**Limiti**:
- un IP condiviso (NAT, server terminal, PC condiviso) o riassegnato dal DHCP può dare persone sbagliate: restano PROBABILI finché l'utente non conferma;
- la password AD è conservata sull'agent con DPAPI;
- il syslog UDP non è autenticato: il filtro sull'indirizzo del firewall non protegge da pacchetti falsificati sulla LAN;
- test solo MOCK: Go `internal/identities` (parsing eventi e syslog, filtro mittente, tabella) e `internal/scan` (ambito, batch); backend `AccountIdentitiesTest`. Mai verificato su un dominio o un Sophos reali.
