# 13 — Utenti, organizzazioni, clienti, abitazioni e reti (Milestone 4)

Questo documento descrive ciò che è **implementato** nella Milestone 4. Le decisioni sono in [TECHNICAL_DECISIONS.md](../TECHNICAL_DECISIONS.md) (ADR-024…ADR-030). Il modello di autenticazione, ruoli e isolamento della Milestone 3 è in [12-AUTHENTICATION.md](12-AUTHENTICATION.md).

## 1. Modello

```
tenant (INDIVIDUAL | BUSINESS) ── plan_code → plans (FREE)
 ├─ organization (solo BUSINESS, 1:1)
 ├─ users ── role_assignments (ruolo + ambito: TENANT | ORGANIZATION | CUSTOMER | HOME)
 ├─ customers (solo BUSINESS)            archiviati, mai cancellati
 └─ homes (customer_id facoltativo)      archiviate, mai cancellate
     └─ networks (solo intervalli privati, dichiarate a mano: source = MANUAL)
         └─ network_authorizations (storico; al massimo una attiva)
```

- Ogni tabella ha `tenant_id` e la **RLS** di PostgreSQL. Il ruolo applicativo non ha `BYPASSRLS`.
- Le chiavi esterne composte `(tenant_id, id)` impediscono riferimenti incrociati tra tenant anche a livello di database.

## 2. Ruoli, ambiti e permessi

| Permesso nuovo | SUPER_ADMIN | ORGANIZATION_ADMIN | TECHNICIAN | CUSTOMER | READ_ONLY |
|---|:-:|:-:|:-:|:-:|:-:|
| `organization:manage` | ✔ | ✔ | | | |
| `customer:read` | ✔ | ✔ | ✔ | ✔ | ✔ |
| `customer:manage` | ✔ | ✔ | | | |
| `network:manage` | ✔ | ✔ | ✔ | ✔ | |
| `network:authorize` | ✔ | ✔ | ✔ | ✔ | |

**Nuovo ambito `CUSTOMER`.** Un ruolo con ambito cliente vale per quel cliente e per tutte le sue abitazioni, comprese quelle create in seguito.

Ambiti assegnabili:
- TECHNICIAN e READ_ONLY: TENANT, ORGANIZATION, CUSTOMER, HOME.
- CUSTOMER: TENANT, CUSTOMER, HOME.

**Regole di accesso** (`AccessPolicy`):
- Una risorsa fuori dal proprio ambito risponde **404**: per l'utente non esiste.
- Una risorsa visibile ma senza il permesso necessario risponde **403**.
- Le operazioni sull'intero tenant richiedono un ruolo con ambito tenant (*tenant-wide*): gestione utenti, organizzazione, creazione/modifica clienti.
- Un utente con `home:write` sul cliente può creare abitazioni **solo per quel cliente**. Spostare un'abitazione tra clienti richiede gli stessi diritti su entrambi.
- Matrice completa verificata da `RoleAuthorizationMatrixTest`: 25 richieste × 5 profili.

## 3. Limiti del piano FREE

| Risorsa | Limite | Conteggio |
|---|---|---|
| Abitazioni | 2 | abitazioni non archiviate |
| Utenti | 3 | utenti non disattivati (inclusi gli invitati) |
| Clienti | 2 | clienti non archiviati |
| Reti per abitazione | 4 | reti dell'abitazione |

- La verifica avviene in transazione con un lock sulla riga del tenant (`SELECT … FOR UPDATE`), quindi due richieste concorrenti non superano il limite.
- Il superamento risponde 409 `PLAN_LIMIT_REACHED`, con `resource`, `limit` e `plan`.
- I limiti valgono per le **nuove** creazioni (e per la riattivazione di un utente). Nessun dato esistente viene toccato.
- Il limite di agent per abitazione è rimandato alla Milestone 5.
- `plans` è una tabella di riferimento non modificabile dal ruolo applicativo. Nessun servizio di pagamento è introdotto.

## 4. Utenti e inviti

1. Un amministratore invia l'invito (`POST /users`) con email, nome, lingua, ruolo e ambito.
   - L'utente è creato **senza password**, in stato `PENDING_VERIFICATION`.
   - Il ruolo passa per gli stessi controlli dell'assegnazione: nessuna escalation, nessun ruolo di piattaforma.
   - Se il ruolo è rifiutato, nulla viene creato.
2. Riceve un'email con un link monouso, valido 7 giorni: `/accept-invitation#token=…`. Il token è nel frammento, quindi non arriva al server né finisce nel Referer.
3. Sceglie la password (`POST /auth/invitation/accept`, pubblico, con CSRF).
   - Si applica la stessa password policy della registrazione.
   - L'account diventa `ACTIVE` con email verificata.
4. "Rinvia invito" invalida il link precedente.

Gestione degli utenti esistenti:
- **Disattivazione** (`PATCH /users/{id} {status: DISABLED}`):
  - revoca **subito** tutte le sessioni e i token monouso dell'utente;
  - vietata su sé stessi (`CANNOT_DISABLE_SELF`) e sull'ultimo amministratore attivo (`LAST_ADMIN`);
  - i ruoli sono conservati.
- **Riattivazione**: soggetta al limite utenti.
- Non esiste la cancellazione fisica degli utenti (ADR-024).

## 5. Reti e autorizzazione

- **Solo intervalli privati o locali**: 10/8, 172.16/12, 192.168/16, 169.254/16, fc00::/7, fe80::/10. Sono esclusi pubblici e CGNAT 100.64/10.
- **Dimensione**: almeno /22 in IPv4 e almeno /64 in IPv6.
- La validazione è applicata due volte:
  1. nell'applicazione (`NetworkRange`): solo letterali numerici, nessuna risoluzione DNS, niente zeri iniziali, niente zone id, bit host a zero;
  2. con vincoli `CHECK` nel database, verificati da un test che scrive direttamente in SQL.
- Le reti della stessa abitazione non possono sovrapporsi (`NETWORK_OVERLAP`). L'intervallo è immutabile: si cambiano solo nome e tipo.
- **Autorizzazione** (`POST /networks/{id}/authorization`):
  - richiede `{attestation: true, attestationVersion: "1"}`. L'utente spunta un testo versionato (`networks.attestation.v1`) che **non è mai preselezionato**.
  - Una versione diversa risponde `ATTESTATION_OUTDATED`.
  - Viene registrato chi, quando e quale versione. Lo storico è conservato e la revoca è possibile.
  - Tutto è registrato nell'audit.
- **Nessuna scansione** viene avviata dichiarando o autorizzando una rete. Le scansioni manuali arriveranno nelle milestone successive e potranno colpire solo reti autorizzate.

## 6. API (implementate)

| Metodo | Path | Permesso | Note |
|---|---|---|---|
| GET | `/tenants/current` | `tenant:read` | piano; uso solo per chi ha ambito tenant |
| GET · PUT | `/organizations/current` | `tenant:read` · `organization:manage` (tenant) | PUT sostituisce tutti i campi; P.IVA normalizzata (`INVALID_VAT_NUMBER`) |
| GET · POST | `/customers` | `customer:read` · `customer:manage` (tenant) | solo tenant BUSINESS (`BUSINESS_TENANT_REQUIRED`) |
| GET · PUT · DELETE | `/customers/{id}` | `customer:read` · `customer:manage` | DELETE archivia; `CUSTOMER_HAS_HOMES` |
| GET · POST | `/homes` (`?customerId=`) | `home:read` · `home:write` | `INVALID_CUSTOMER`, `INVALID_TIMEZONE` |
| GET · PUT · DELETE | `/homes/{id}` | `home:read` · `home:write` | DELETE archivia; `HOME_HAS_ACTIVE_AGENTS` |
| GET · POST | `/homes/{id}/networks` | `home:read` · `network:manage` | `INVALID_CIDR`, `NETWORK_NOT_PRIVATE`, `NETWORK_TOO_LARGE`, `NETWORK_OVERLAP` |
| PUT · DELETE | `/networks/{id}` | `network:manage` | solo nome e tipo |
| POST · DELETE | `/networks/{id}/authorization` | `network:authorize` | `ATTESTATION_REQUIRED`, `ATTESTATION_OUTDATED`, `NETWORK_ALREADY_AUTHORIZED`, `NETWORK_NOT_AUTHORIZED` |
| GET · POST | `/users` | `user:read` · `user:manage` (tenant) | POST = invito (limitato per IP); `EMAIL_ALREADY_REGISTERED` |
| GET · PATCH | `/users/{id}` | `user:read` · `user:manage` (tenant) | PATCH parziale: `displayName`, `status` (`ACTIVE`/`DISABLED`) |
| POST | `/users/{id}/invitation` | `user:manage` (tenant) | `INVITATION_NOT_PENDING` |
| POST | `/auth/invitation/accept` | pubblico + CSRF | `{token, newPassword}` → 204 |

Gli endpoint dei ruoli della Milestone 3 restano invariati e ora accettano anche l'ambito `CUSTOMER`: `GET /roles` e `GET/POST/DELETE /users/{id}/roles`.

**Eventi di audit nuovi**:
- utenti: `USER_INVITED`, `USER_INVITATION_RESENT`, `INVITATION_ACCEPTED`, `INVITATION_ACCEPT_FAILED`, `USER_UPDATED`, `USER_DISABLED`, `USER_ENABLED`;
- organizzazione e clienti: `ORGANIZATION_UPDATED`, `CUSTOMER_CREATED`, `CUSTOMER_UPDATED`, `CUSTOMER_ARCHIVED`;
- abitazioni: `HOME_UPDATED`, `HOME_ARCHIVED`;
- reti: `NETWORK_CREATED`, `NETWORK_UPDATED`, `NETWORK_DELETED`, `NETWORK_AUTHORIZED`, `NETWORK_AUTHORIZATION_REVOKED`.

## 7. Dashboard

| Pagina | Contenuto |
|---|---|
| **Abitazioni** | Filtro per cliente. Creazione con selezione del cliente: chi ha un ambito cliente vede solo i propri clienti, senza l'opzione "nessun cliente". |
| **Dettaglio abitazione** | Modifica dei dati e archiviazione con conferma. Sezione **Reti** con dichiarazione, attestazione esplicita per autorizzare, revoca ed eliminazione con conferma. |
| **Clienti** | Solo account aziendali. Elenco per chi ha `customer:read`; creazione, modifica e archiviazione (con conferma) per chi ha `customer:manage`. |
| **Utenti** | Elenco con stato e ruoli. Invito con ruolo e ambito; rinvio dell'invito; disattivazione con conferma e riattivazione; aggiunta e rimozione di ruoli con conferma. |
| **Organizzazione** | Piano e uso rispetto ai limiti. Dati aziendali, in sola lettura senza `organization:manage`. |
| **Attiva account** | Pagina pubblica `/accept-invitation`. |

Le voci di menu e i pulsanti dipendono dai permessi del profilo, ma sono solo un aiuto: **decide sempre il backend**. Tutti i nuovi testi sono in italiano e inglese.

## 8. Test

**Backend** (Testcontainers, PostgreSQL 18 reale con RLS):
- `UserManagementTest` (7): invito e attivazione, escalation, email esistente, disattivazione immediata, ultimo amministratore, rinvio, limite utenti, isolamento.
- `CustomersHomesAndPlanTest` (9): piano e uso, organizzazione, clienti B2B/B2C, ambito cliente, tecnico in sola lettura sui clienti, archiviazioni, limiti FREE, isolamento.
- `NetworkManagementTest` (7): reti private, sovrapposizioni, limite per abitazione, attestazione, ruoli e ambiti, isolamento, vincoli DB.
- `NetworkRangeTest` (33 casi parametrizzati).
- `RoleAuthorizationMatrixTest`: la matrice per ruolo.

**Frontend**: spec per utenti, clienti, organizzazione, attivazione account, abitazioni con clienti, reti e attestazione nel dettaglio abitazione.
