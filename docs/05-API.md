# 05 — API REST (`/api/v1`)

Convenzioni: JSON, errori **RFC 9457 Problem Details** (`type`, `title`, `status`, `detail`, `code`, `traceId`), paginazione `?page&size&sort` con `X-Total-Count`, date ISO-8601 UTC, `Idempotency-Key` sulle POST che creano risorse costose, OpenAPI 3.1 su `/api/v1/openapi.json` + Swagger UI (disabilitata in produzione o protetta). Le API utente usano JWT utente; le API `/agent/**` usano solo token agent (§Agent). Tutti gli ID sono UUID; un ID di altro tenant restituisce **404** (non 403) per non rivelarne l'esistenza.

> **Stato (Milestone 3)**: gli endpoint di autenticazione, account, sessioni, utenti/ruoli, case (creazione e lettura), token di enrollment, gestione agent, audit e API agent (`enroll`, `token`, `session`, `credentials/rotate`) sono **implementati**. Contratto esatto in [12-AUTHENTICATION.md](12-AUTHENTICATION.md). Gli altri endpoint di questo documento restano il progetto per le milestone successive. MFA (`/auth/mfa/*`) è predisposta ma non ancora implementata.
>
> **Stato (Milestone 4)**: utenti (invito, attivazione, disattivazione), organizzazione, piano/uso, clienti, homes (modifica, archiviazione) e reti con autorizzazione sono **implementati**. Contratto esatto in [13-USERS-ORGANIZATIONS-NETWORKS.md](13-USERS-ORGANIZATIONS-NETWORKS.md). Rispetto al progetto iniziale:
> - le modifiche di organizzazione, clienti, homes e reti usano **PUT** (sostituzione completa); `PATCH /users/{id}` resta parziale;
> - l'autorizzazione di una rete è `POST/DELETE /networks/{id}/authorization`;
> - `DELETE` su homes e clienti **archivia**, non cancella;
> - gli utenti non si cancellano: si disattivano.

## Authentication
| Metodo | Path | Descrizione |
|---|---|---|
| POST | `/auth/register` | registrazione B2C (crea tenant INDIVIDUAL + piano FREE) o B2B (tenant BUSINESS) |
| POST | `/auth/verify-email` | conferma email |
| POST | `/auth/login` | email+password → access token, oppure `mfaRequired` + `mfaToken` |
| POST | `/auth/mfa/verify` | codice TOTP/recovery → access token |
| POST | `/auth/refresh` | cookie refresh HttpOnly → nuovo access + refresh (rotation) |
| POST | `/auth/logout` | revoca famiglia refresh |
| POST | `/auth/password/forgot` · `/auth/password/reset` | reset con token monouso |
| POST/DELETE | `/auth/mfa/totp` | attivazione (QR + conferma) / disattivazione |

## Users · Tenants · Organizations
`GET/PATCH /me` · `GET/POST /users` (POST = invito) · `GET/PATCH /users/{id}` · `POST /users/{id}/invitation` · `GET /roles` · `GET/POST /users/{id}/roles` · `DELETE /users/{id}/roles/{assignmentId}` · `POST /auth/invitation/accept` · `GET /tenants/current` · `GET/PUT /organizations/current` · `GET/POST /customers` · `GET/PUT/DELETE /customers/{id}`

## Homes · Networks
`GET/POST /homes` (`?customerId=`) · `GET/PUT/DELETE /homes/{homeId}` · `GET/POST /homes/{homeId}/networks` · `PUT/DELETE /networks/{networkId}` · `POST/DELETE /networks/{networkId}/authorization` (con attestazione versionata) · `GET /homes/{homeId}/overview` (score, contatori, ultima scansione, stato agent, copertura — milestone successive)

## Agents
| Metodo | Path | Descrizione |
|---|---|---|
| POST | `/homes/{homeId}/agent-enrollment-tokens` | genera token (mostrato una volta) |
| DELETE | `/agent-enrollment-tokens/{id}` | revoca token |
| GET | `/homes/{homeId}/agents` · `/agents/{id}` | stato, versione, capabilities, heartbeat |
| POST | `/agents/{id}/revoke` | revoca credenziali |
| GET | `/agents/{id}/events` | eventi |

## Scans
| Metodo | Path | Descrizione |
|---|---|---|
| POST | `/homes/{homeId}/scans` | **crea scansione manuale** `{profile, target: {type: ALL_AUTHORIZED} \| {type: DEVICES, deviceIds[]}}` → `202` |
| GET | `/homes/{homeId}/scans` | storico (filtri stato/data) |
| GET | `/scans/{scanId}` | stato, avanzamento, contatori, warning/errori |
| POST | `/scans/{scanId}/cancel` | richiesta annullamento → `202` |
| GET | `/scans/{scanId}/devices` · `/findings` · `/diff` | risultati e variazioni vs scansione precedente |

## Devices · Discovery · Fingerprinting · Ports · Services
`GET /homes/{homeId}/devices?category&confidence&online&unknown` · `GET /devices/{id}` · `PATCH /devices/{id}` (display_name) · **`PUT /devices/{id}/classification` `{category}`** (manuale; `DELETE` per tornare all'automatica) · `GET /devices/{id}/identifications` (confidenza per campo con fonti) · `GET /devices/{id}/observations` · `GET /devices/{id}/ports` · `GET /devices/{id}/services` · `GET /devices/{id}/protocols` · `GET /devices/{id}/scans` · `GET /homes/{homeId}/network-map`

## Findings · Vulnerabilities · Risk
`GET /homes/{homeId}/findings?severity&status&type` · `GET /findings/{id}` (con evidenze) · `PATCH /findings/{id}/status` (`ACKNOWLEDGED`, `FALSE_POSITIVE`, `ACCEPTED_RISK` con motivazione) · `GET /homes/{homeId}/vulnerabilities` · `GET /vulnerabilities/{cveId}` · `GET /homes/{homeId}/risk` (snapshot corrente + spiegazione) · `GET /homes/{homeId}/risk/history`

## Alerts · Reports
`GET /alerts?unread` · `POST /alerts/{id}/read` · `GET/PUT /notification-preferences` · `POST /push-devices` · `POST /scans/{scanId}/reports` `{locale}` → `202` · `GET /reports/{id}` · `GET /reports/{id}/download`

## Subscriptions · Integrations · Administration
`GET /plans` · `GET /subscription` · `POST /subscription/checkout-session` · `POST /subscription/portal-session` · `GET /payments` · `POST /webhooks/stripe` (pubblico, firma verificata) · `GET/POST /homes/{homeId}/integrations` · `DELETE /integrations/{id}` · `/admin/**` (solo SUPER_ADMIN, audit obbligatorio): tenants, utenti, agent, feed status, piani.

## Agent API (`/api/v1/agent`, solo token agent)
`POST /enroll` · `POST /token` · `POST /credentials/rotate` · `POST /heartbeat` · `GET /jobs/next?wait=30` · `POST /scans/{id}/ack` · `POST /scans/{id}/progress` · `POST /scans/{id}/results` · `POST /scans/{id}/complete` · `GET /updates/manifest` · `GET /oui/snapshot` (ETag)

## Trasversali
- **Validazione**: Jakarta Bean Validation sui DTO, dimensione max body (agent 2 MB/batch compresso), whitelist enum.
- **Autorizzazione**: `@PreAuthorize` con permessi + verifica di scope (cliente/home) in un `AccessPolicy` centrale.
- **Rate limiting**: Nginx `limit_req` per IP + Bucket4j (backend Postgres, nessun Redis nell'MVP) per utente/tenant/agent; login: 5 tentativi/min/IP+account, lockout progressivo.
- **Logging**: JSON strutturato, `traceId` per richiesta, nessun segreto/token/password nei log, IP e MAC trattati come dati personali.
