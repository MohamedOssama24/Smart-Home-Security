# 05 — API REST (`/api/v1`)

> **Milestone 6**: endpoint delle scansioni (utente e agent) implementati come descritto in [15-MANUAL-SCANS.md](15-MANUAL-SCANS.md) §3-§7.

> **Milestone 7**: `GET /api/v1/scans/{id}/devices` raggruppa gli indirizzi per MAC e restituisce `addresses`, `hostname`, `hostnames`, `evidence`; i risultati inviati dall'agent accettano `hostname` e `details` (400 `DETAILS_TOO_LARGE`). Vedi [16-NETWORK-DISCOVERY.md](16-NETWORK-DISCOVERY.md) §5.

Convenzioni: JSON, errori **RFC 9457 Problem Details** (`type`, `title`, `status`, `detail`, `code`, `traceId`), paginazione `?page&size&sort` con `X-Total-Count`, date ISO-8601 UTC, `Idempotency-Key` sulle POST che creano risorse costose, OpenAPI 3.1 su `/api/v1/openapi.json` + Swagger UI (disabilitata in produzione o protetta). Le API utente usano JWT utente; le API `/agent/**` usano solo token agent (§Agent). Tutti gli ID sono UUID; un ID di altro tenant restituisce **404** (non 403) per non rivelarne l'esistenza.

> **Stato (Milestone 3)**: gli endpoint di autenticazione, account, sessioni, utenti/ruoli, case (creazione e lettura), token di enrollment, gestione agent, audit e API agent (`enroll`, `token`, `session`, `credentials/rotate`) sono **implementati**. Contratto esatto in [12-AUTHENTICATION.md](12-AUTHENTICATION.md). Gli altri endpoint di questo documento restano il progetto per le milestone successive. MFA (`/auth/mfa/*`) è predisposta ma non ancora implementata.
>
> **Stato (Milestone 4)**: utenti (invito, attivazione, disattivazione), organizzazione, piano/uso, clienti, homes (modifica, archiviazione) e reti con autorizzazione sono **implementati**. Contratto esatto in [13-USERS-ORGANIZATIONS-NETWORKS.md](13-USERS-ORGANIZATIONS-NETWORKS.md). Rispetto al progetto iniziale:
> - le modifiche di organizzazione, clienti, homes e reti usano **PUT** (sostituzione completa); `PATCH /users/{id}` resta parziale;
> - l'autorizzazione di una rete è `POST/DELETE /networks/{id}/authorization`;
> - `DELETE` su homes e clienti **archivia**, non cancella;
> - gli utenti non si cancellano: si disattivano.
>
> **Stato (Milestone 5)**: `POST /agent/heartbeat`, `POST /agent/events` e `GET /agents/{id}/events` sono **implementati**; le risposte agent includono connettività e autodiagnosi; limite di 2 agent attivi per abitazione nel piano FREE. Contratto esatto in [14-AGENT-RUNTIME.md](14-AGENT-RUNTIME.md).

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
| GET | `/homes/{homeId}/agent-enrollment-tokens` | elenco token (stato, scadenza; mai il valore) |
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
> **Implementato (M8)**: `GET /homes/{homeId}/devices` · `GET /devices/{id}` (con `identifications` e `categoryHistory`) · `PUT /devices/{id}/category` `{category}` (`null` = torna all'automatica; `400 INVALID_CATEGORY`) · `GET /platform/oui` · `POST /platform/oui/sync` (solo `platform:admin`). Vedi [17-DEVICE-FINGERPRINTING.md](17-DEVICE-FINGERPRINTING.md) §8. Il resto della sezione è pianificato.

> **Implementato (M9)**: `GET /scans/{id}/ports` (porte aperte e servizi) · `GET /devices/{id}` con `services` (contatori, porte, protocolli dell'ultima scansione delle porte) · profili `QUICK`/`STANDARD` in `POST /homes/{homeId}/scans`. Vedi [18-PORT-SCANNING.md](18-PORT-SCANNING.md) §8.

`GET /homes/{homeId}/devices?category&confidence&online&unknown` · `GET /devices/{id}` · `PATCH /devices/{id}` (display_name) · **`PUT /devices/{id}/classification` `{category}`** (manuale; `DELETE` per tornare all'automatica) · `GET /devices/{id}/identifications` (confidenza per campo con fonti) · `GET /devices/{id}/observations` · `GET /devices/{id}/ports` · `GET /devices/{id}/services` · `GET /devices/{id}/protocols` · `GET /devices/{id}/scans` · `GET /homes/{homeId}/network-map`

## Findings · Vulnerabilities · Risk
> **Milestone 10**: implementati `GET /homes/{homeId}/findings`, `GET /findings/{id}` (evidenze e CVE collegate con KEV/EPSS), `PATCH /findings/{id}/status` (anche `OPEN` per riaprire; `409 FINDING_RESOLVED`), `GET /vulnerabilities/{cveId}`, `GET|POST /platform/vulnerabilities[/sync]` (amministratore di piattaforma). `GET /homes/{homeId}/vulnerabilities` e il rischio: M11 (nota sotto). Vedi [19-SECURITY-ANALYSIS.md](19-SECURITY-ANALYSIS.md) §6.
>
> **Milestone 11**: implementati `GET /homes/{homeId}/risk` (`current` + `lastScored`, con breakdown, copertura e delta), `GET /homes/{homeId}/risk/history?limit` (1–100, `400 INVALID_LIMIT`) e `GET /homes/{homeId}/vulnerabilities`; permesso `finding:read`. Vedi [20-RISK-ENGINE.md](20-RISK-ENGINE.md) §6.

> **Milestone 12**: `GET /overview`: abitazioni visibili (`home:read`) con, dove l'utente ha `finding:read`, ultimo punteggio calcolato, motivo dello snapshot non calcolato, finding conteggiati per gravità, KEV, dispositivi e ultima scansione (`security` nullo altrimenti). Vedi [21-DASHBOARD.md](21-DASHBOARD.md) §2 e ADR-065.

`GET /homes/{homeId}/findings?severity&status&type` · `GET /findings/{id}` (con evidenze) · `PATCH /findings/{id}/status` (`ACKNOWLEDGED`, `FALSE_POSITIVE`, `ACCEPTED_RISK` con motivazione) · `GET /homes/{homeId}/vulnerabilities` · `GET /vulnerabilities/{cveId}` · `GET /homes/{homeId}/risk` (snapshot corrente + spiegazione) · `GET /homes/{homeId}/risk/history`

## Alerts · Reports
> **Milestone 13**: implementati `GET /alerts?unread&limit`, `GET /alerts/unread-count`, `POST /alerts/{id}/read`, `POST /alerts/read-all`, `GET/PUT /notification-preferences`, `POST /scans/{scanId}/reports` → `202`, `GET /reports/{id}`, `GET /homes/{homeId}/reports`, `GET /reports/{id}/download`; nuovo permesso `report:generate`. `POST /push-devices` arriva con l'app (M14). Vedi [22-ALERTS-REPORTS.md](22-ALERTS-REPORTS.md) §2.

> **Milestone 14**: implementati `POST /auth/mobile/login|refresh|logout` (refresh token nel body, niente cookie né CSRF) e `GET/POST /push-devices`, `DELETE /push-devices/{id}`; canale `PUSH` nelle preferenze di notifica. Vedi [23-MOBILE-APP.md](23-MOBILE-APP.md) §2-§3 e ADR-069.

> **Milestone 15**: implementato `GET /scans/{scanId}/integrations` (`scan:read`) → inventario Home Assistant della scansione (versione, https, conteggi per protocollo, dispositivi con `matchedIp`). La configurazione di Home Assistant resta sull'agent: le route `GET/POST /homes/{homeId}/integrations` e `DELETE /integrations/{id}` sono state rimosse dal disegno (decisione confermata). Vedi [24-INTEGRATIONS.md](24-INTEGRATIONS.md) e ADR-070.

> **Milestone 16 — Assistente**: `POST /homes/{homeId}/assistant/questions` con `{question (1–500 caratteri, senza caratteri di controllo tranne a capo), locale: it|en}` → `{answer, citations[{id, kind: SCORE|FINDING|DEVICE, label, severity, ip}], provider, fallback, fallbackReason, scanId, dataAsOf, generatedAt}`. Richiede `device:read` e `finding:read` sull'abitazione; casa di un altro tenant → 404; 20 domande/minuto per utente → 429. Sola lettura, nessuna azione, nessun salvataggio di domande o risposte. Vedi [25-AI-ASSISTANT.md](25-AI-ASSISTANT.md) e ADR-071.

`GET /alerts?unread` · `POST /alerts/{id}/read` · `GET/PUT /notification-preferences` · `POST /push-devices` · `POST /scans/{scanId}/reports` `{locale}` → `202` · `GET /reports/{id}` · `GET /reports/{id}/download`

## Subscriptions · Integrations · Administration
`GET /billing` (piano attuale, sottoscrizione, piani acquistabili dal tipo di tenant) · `POST /billing/checkout` `{planCode}` → `{url}` Stripe Checkout · `POST /billing/portal` → `{url}` Billing Portal · `POST /billing/stripe/webhook` (pubblico, firma `Stripe-Signature` verificata, idempotente) · `GET/PUT /branding` · `PUT/DELETE/GET /branding/logo` (PNG/JPEG) · `GET /scans/{scanId}/integrations` (sola lettura; la configurazione di Home Assistant resta sull'agent, nessun token al backend: ADR-070) · `/admin/**` (solo SUPER_ADMIN, audit obbligatorio): tenants, utenti, agent, feed status, piani.

> **Milestone 17 — Abbonamenti e white label**: `/billing`, `/billing/checkout` e `/billing/portal` richiedono `billing:manage` a livello tenant (ORGANIZATION_ADMIN, CUSTOMER del B2C); senza chiavi Stripe → 503 `BILLING_DISABLED`. `GET /billing` include `trialDays` (prova offerta al checkout, 0 = nessuna) e `subscription.trialEnd`. Errori: `PLAN_NOT_AVAILABLE` (400), `SUBSCRIPTION_EXISTS` / `NO_SUBSCRIPTION` (409), `BILLING_PROVIDER_ERROR` (502). Il webhook risponde `{outcome: APPLIED|DUPLICATE|STALE|IGNORED}`; firma non valida → 400 `INVALID_SIGNATURE`. `GET /branding` (`tenant:read`) → `{available, displayName, primaryColor, supportEmail, logoSha256, updatedAt}`; le modifiche richiedono `organization:manage` a livello tenant e un piano con white label, altrimenti 409 `PLAN_FEATURE_UNAVAILABLE`. Non implementati in M17: `GET /payments` (fatture nel Billing Portal) e `/admin/**`. Vedi [26-SAAS-BILLING.md](26-SAAS-BILLING.md) e ADR-072.

## Agent API (`/api/v1/agent`, solo token agent)
`POST /enroll` · `POST /token` · `POST /credentials/rotate` · `POST /heartbeat` · `GET /jobs/next?wait=30` · `POST /scans/{id}/ack` · `POST /scans/{id}/progress` · `POST /scans/{id}/results` · `POST /scans/{id}/complete` · `GET /updates/manifest` · `GET /oui/snapshot` (ETag)

## Audit
`GET /audit-logs?limit=` — eventi del proprio tenant, più recenti prima (implementato dalla Milestone 3, vedi [12-AUTHENTICATION.md](12-AUTHENTICATION.md)).

## Trasversali
- **Validazione**: Jakarta Bean Validation sui DTO, dimensione max body (agent 2 MB/batch compresso), whitelist enum.
- **Autorizzazione**: `@PreAuthorize` con permessi + verifica di scope (cliente/home) in un `AccessPolicy` centrale.
- **Rate limiting**: Nginx `limit_req` per IP + Bucket4j (backend Postgres, nessun Redis nell'MVP) per utente/tenant/agent; login: 5 tentativi/min/IP+account, lockout progressivo.
- **Logging**: JSON strutturato, `traceId` per richiesta, nessun segreto/token/password nei log, IP e MAC trattati come dati personali.
