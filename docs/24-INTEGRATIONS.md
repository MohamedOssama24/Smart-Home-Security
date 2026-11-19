# 24 — Integrazioni: Home Assistant e valutazione Matter (Milestone 15)

> Stato: implementato (Home Assistant), valutato (Matter). Decisione: ADR-070.

## 1. Obiettivo
Rendere visibili i dispositivi che la scansione IP non vede (Zigbee, Z-Wave, Thread, Bluetooth: limite L5 di [10-RISKS-LIMITATIONS.md](10-RISKS-LIMITATIONS.md)) leggendo l'inventario di **Home Assistant** del proprietario con l'**API REST ufficiale** e un **token di lunga durata creato dal proprietario**. Integrazione in sola lettura, senza servizi a pagamento né nuove dipendenze.

## 2. Architettura e sicurezza
Home Assistant è nella LAN di casa: lo contatta **l'agent**, come le integrazioni router ([16-NETWORK-DISCOVERY.md](16-NETWORK-DISCOVERY.md) §4).

- **Configurazione solo sull'agent** (`secret_location = AGENT_LOCAL`):
  `shsc-agent homeassistant set --url http://IP:8123 [--tls-server-name NOME]` (token letto da stdin, mai stampato), `show` (URL senza token), `remove`. Salvati in `homeassistant.json`, protetto come la chiave (DPAPI su Windows, 0600 altrove), cancellato da `Retire`. Il backend non riceve mai URL completo né token.
- **Solo indirizzo IP letterale** (nessuna risoluzione di nomi), nessun percorso, nessuna user-info. HTTPS con verifica del certificato (TLS ≥ 1.2); `--tls-server-name` se il certificato riporta un nome invece dell'IP. Nessun `InsecureSkipVerify`.
- **Nell'ambito**: Home Assistant viene contattato solo se il suo IP appartiene alle reti autorizzate del job (`HA_OUT_OF_SCOPE` altrimenti, nessun pacchetto). Il backend riapplica il controllo e scarta l'inventario di un IP fuori ambito (contato in `dropped`, audit `SCAN_RESULTS_OUT_OF_SCOPE`).
- **Client HTTP chiuso**: si connette solo a IP:porta configurati, nessun proxy, nessun redirect, timeout 15 s, risposta ≤ 4 MB.
- **Sola lettura**: `GET /api/config` (solo il campo `version`; posizione e nome della casa ignorati) e `POST /api/template` (render di un template che legge il registro dispositivi; non modifica nulla). Nessun servizio chiamato, nessuno stato modificato.
- **Token rifiutato** (401/403): `HA_AUTH_FAILED`, un solo tentativo, nessun retry.
- **HTTP in chiaro**: consentito (è il default di Home Assistant) ma segnalato con `HA_PLAIN_HTTP` e in dashboard.
- Avvisi: `HA_OUT_OF_SCOPE`, `HA_UNREACHABLE`, `HA_AUTH_FAILED`, `HA_INVALID_RESPONSE`, `HA_PLAIN_HTTP`, `HA_INVENTORY_TRUNCATED`. Ognuno porta la scansione a `COMPLETED_WITH_WARNINGS`.

## 3. Dati
Per ogni dispositivo con almeno un'entità: nome, produttore, modello, firmware, **protocollo** (`ZIGBEE`, `ZWAVE`, `MATTER`, `THREAD`, `BLUETOOTH`, `IP`, `OTHER`), MAC (connessioni `mac`, max 8), numero di entità. Gli identificativi interni (IEEE, seriali) servono solo a classificare e non lasciano l'agent.

Classificazione: dominio dell'integrazione negli identificatori (`zha`/`deconz`/`zigbee2mqtt` → Zigbee, `zwave_js` → Z-Wave, `matter` → Matter, `thread`/`otbr` → Thread, `bluetooth`/`bthome`/`ibeacon`/`*_ble` → Bluetooth), poi il tipo di connessione (`zigbee`, `bluetooth`, `mac` → IP), altrimenti `OTHER`.

Testi ripuliti dai caratteri di controllo e troncati; max 500 dispositivi (`truncated`).

- **Upload**: campo `homeAssistant` di un batch dedicato di `POST /api/v1/agent/scans/{id}/results` (senza porte); uno per scansione (un secondo → 409 `HOME_ASSISTANT_ALREADY_UPLOADED`; stesso batch → no-op idempotente).
- **Database** (`V014__home_assistant.sql`, RLS per tenant): `scan_home_assistant` (IP, versione, https, conteggio, troncato) e `scan_gateway_devices`.
- **API**: `GET /api/v1/scans/{id}/integrations` (`scan:read`; altri tenant 404) → `homeAssistant` con conteggi per protocollo e dispositivi; `matchedIp` = host della stessa scansione con uno dei MAC del dispositivo.
- **Dashboard**: sezione "Home Assistant" nel dettaglio della scansione (protocolli, dispositivi, avviso HTTP). I dati sono dichiarati dalle integrazioni di Home Assistant: non verificati, non entrano nel punteggio di rischio.

## 4. Valutazione Matter
| Opzione | Esito |
|---|---|
| **Via Home Assistant** (integrazione Matter del proprietario) | **Adottata**: i dispositivi Matter compaiono nell'inventario con protocollo `MATTER`, senza credenziali aggiuntive. |
| Osservazione passiva mDNS (`_matter._tcp` operativo, `_matterc._udp` in commissioning) | Possibile in futuro con il discovery mDNS esistente: un dispositivo che annuncia `_matterc._udp` a lungo ha la finestra di commissioning aperta. Non implementata in M15 (fuori dalla riga di roadmap). |
| Controller Matter proprio (SDK CHIP / python-matter-server) | **Scartata**: richiede di entrare nel fabric con il codice di setup (azione attiva sul dispositivo), dipendenze pesanti, capacità di scrittura. Contrario al principio "sola lettura". |

Matter cifra e autentica le sessioni (PASE/CASE, certificati di attestazione): senza far parte del fabric non si leggono attributi. La via sicura è delegare al controller già scelto dal proprietario (Home Assistant).

## 5. Limiti
- Solo dispositivi con almeno un'entità; nessun dato su aree, automazioni, utenti o add-on.
- Il token di lunga durata ha i permessi del suo utente; l'agent usa solo le due chiamate di lettura descritte sopra. Verificato solo con l'utente proprietario (amministratore) creato dall'onboarding.
- Correlazione con la scansione solo per MAC (molti dispositivi Wi-Fi non espongono il MAC in Home Assistant).
- Nessuna analisi di sicurezza di Home Assistant stessa oltre a HTTP in chiaro (la versione è mostrata, non confrontata con le vulnerabilità note).

## 6. Test
- **Agent** (`internal/homeassistant`, `internal/scan`): Home Assistant **[MOCK]** su loopback — inventario e classificazione, MAC normalizzati e deduplicati, caratteri di controllo rimossi, token rifiutato con una sola richiesta, nessuna richiesta fuori ambito, redirect non seguito, irraggiungibile, validazione della configurazione (errori senza token), store protetto e rimozione, batch senza token né URL.
- **Home Assistant reale in container**: `sh infrastructure/scripts/test-homeassistant.sh` avvia `ghcr.io/home-assistant/home-assistant:2026.11.2` con l'integrazione `demo` (dispositivi **[MOCK]**) su `127.0.0.1`, crea un utente di test con l'API di onboarding (password casuale, mai stampata), ottiene un token e lancia `TestRealHomeAssistant` (inventario reale e token non valido). Container, rete e configurazione vengono rimossi. Esito del 18/11/2026: PASS; template accettato, inventario con i dispositivi "Sun" e "Backup" (`OTHER`), token non valido rifiutato. I dispositivi `demo` non risultano nel registro con entità al momento della lettura, quindi la classificazione Zigbee/Z-Wave/Matter è coperta solo dai test **[MOCK]**.
- **Backend**: `HomeAssistantIntegrationTest` (validazione, ambito, idempotenza, 409, correlazione MAC, isolamento tenant).
- **Dashboard**: `scans.page.spec.ts` (sezione Home Assistant).
