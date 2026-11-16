# 12 — Autenticazione, sessioni, RBAC e identità agent (Milestone 3)

Stato: **implementato e verificato** (test automatici + verifica end-to-end sullo stack Docker).
Decisioni correlate: ADR-005, ADR-017…ADR-023 in [TECHNICAL_DECISIONS.md](../TECHNICAL_DECISIONS.md).

## 1. Architettura

```
Browser (Angular)                         Nginx (TLS, CSP, rate limit)              Spring Boot API                         PostgreSQL 18
 access token in memoria (signal)  ──►  /api/v1/auth/** 30 r/min/IP  ──►  Chain 2 /api/**: JWT ES256 + CSRF + CORS ──►  RLS per tenant
 refresh token = cookie HttpOnly                                             Chain 1 /api/v1/agent/**: token agent opaco      (app.tenant_id per transazione)
 CSRF = cookie XSRF-TOKEN + header                                           Chain 3 resto: tutto negato (tranne health)
Agent Go (Ed25519)                 ──►  /api/v1/agent/**              ──►
```

Tre `SecurityFilterChain` separate garantiscono che **un JWT utente non sia mai accettato sulle API agent** e viceversa:

| Chain | Path | Autenticazione | CSRF |
|---|---|---|---|
| 1 | `/api/v1/agent/**` | `AgentAuthenticationFilter`: token opaco `shsc_at_` (hash in DB), controlla token + credenziale + stato agent a ogni richiesta | no (nessun cookie) |
| 2 | `/api/**` | OAuth2 Resource Server, JWT ES256 utente | sì, solo su POST/PUT/PATCH/DELETE di `/api/v1/auth/**` (gli unici endpoint che usano cookie) |
| 3 | tutto il resto | — | — (solo `/actuator/health*`, `/error`, Swagger se abilitato) |

### Moduli (package `com.shsc`)
| Modulo | Package | Responsabilità |
|---|---|---|
| Authentication | `identity.authentication` | registrazione, verifica email, login, reset password, throttling (`AuthThrottle`), token monouso (`ActionTokenRepository`) |
| User Management | `identity.user` | `/me`, profilo, elenco utenti del tenant |
| Token | `identity.token` | chiave ES256 (`JwtKeys`), emissione/verifica JWT, cookie refresh |
| Session | `identity.session` | sessioni per dispositivo, rotazione refresh, rilevamento riuso, revoca |
| Role / Permission | `identity.role`, `identity.access` | catalogo ruoli/permessi dal DB, assegnazioni con scope, `AccessPolicy`, prevenzione escalation |
| Password | `identity.password` | Argon2id, policy, cambio password |
| Agent Authentication | `agents.auth`, `agents.management` | token di enrollment, identità Ed25519, asserzioni, token agent, rotazione e revoca |
| Audit Logging | `audit` | `AuditLog` append-only, `GET /api/v1/audit-logs` |
| Infrastruttura condivisa | `shared.persistence`, `shared.web`, `security` | contesto tenant per transazione, Problem Details, catene di sicurezza, job di pulizia |

**Estendibilità**:
- **MFA**: `users.mfa_enabled` è già presente. Il login è un servizio applicativo (`AuthenticationService.login`) che restituisce un `TokenResponse`. Per la MFA basterà un passo intermedio (`mfaRequired` + token monouso del tipo `MFA_CHALLENGE` in `user_action_tokens`) senza toccare sessioni, JWT o RBAC.
- **OAuth2/OIDC**: `users.password_hash` è nullable. La sessione nasce da `SessionService.open(user, …)` indipendentemente da come l'utente si è autenticato. Un login OIDC (Spring `oauth2Login`) dovrà solo risolvere l'utente e chiamare lo stesso metodo.

## 2. Endpoint implementati

Errori: RFC 9457 Problem Details con `code` stabile. Le richieste con un ID di un altro tenant ricevono **404**.

### Autenticazione utente — `/api/v1/auth` (cookie + CSRF)
| Metodo | Path | Note |
|---|---|---|
| GET | `/csrf` | emette il cookie `XSRF-TOKEN` (204) |
| POST | `/register` | `{email,password,displayName,locale,accountType: INDIVIDUAL\|BUSINESS,organizationName?}`. Risponde **sempre 202**. Se l'email esiste già, invia una mail "account già esistente" invece di rivelarlo |
| POST | `/verify-email` | `{token}` → 204; token monouso 24 h |
| POST | `/verify-email/resend` | `{email}` → sempre 202 |
| POST | `/login` | `{email,password,deviceLabel?}` → `{accessToken,expiresIn,expiresAt,sessionId}` + cookie `shsc_rt`. 401 `INVALID_CREDENTIALS` identico per email inesistente o password errata; 403 `EMAIL_NOT_VERIFIED` solo con la password corretta; 429 `TOO_MANY_ATTEMPTS` con `Retry-After` |
| POST | `/refresh` | cookie `shsc_rt` → nuovo access token e **nuovo** cookie (rotazione) |
| POST | `/logout` | revoca la sessione corrente e cancella il cookie |
| POST | `/password/forgot` | `{email}` → sempre 202; token 30 min |
| POST | `/password/reset` | `{token,newPassword}` → 204; revoca **tutte** le sessioni |

### Account — `/api/v1/me` (Bearer JWT)
`GET /me` · `PATCH /me` `{displayName,locale}` · `POST /me/password` `{currentPassword,newPassword}` (revoca le altre sessioni) · `GET /me/sessions` · `DELETE /me/sessions/{id}` · `POST /me/sessions/revoke-all` `{includeCurrent}`

### Utenti e ruoli (Bearer JWT, permesso `user:read` / `role:manage`)
`GET /users` · `GET /roles` · `GET /users/{id}/roles` · `POST /users/{id}/roles` `{role,scopeType,scopeId?}` · `DELETE /users/{id}/roles/{assignmentId}`

### Case e agent (Bearer JWT)
`POST/GET /homes` · `GET /homes/{id}` · `POST/GET /homes/{id}/agent-enrollment-tokens` · `DELETE /agent-enrollment-tokens/{id}` · `GET /homes/{id}/agents` · `GET /agents/{id}` · `POST /agents/{id}/revoke` `{reason?}`

### Audit (Bearer JWT, `audit:read` a livello tenant)
`GET /audit-logs?limit=` — eventi del proprio tenant, più recenti prima

### API agent — `/api/v1/agent` (mai JWT utente)
| Metodo | Path | Autenticazione |
|---|---|---|
| POST | `/enroll` | token di enrollment monouso `{enrollmentToken, publicKey (Ed25519 raw base64url), name, hostname, os, arch, agentVersion}` |
| POST | `/token` | asserzione JWS EdDSA firmata dall'agent → token `shsc_at_` 10 min |
| GET | `/session` | token agent: identità, casa associata, scadenza |
| POST | `/credentials/rotate` | token agent + prova firmata con la **nuova** chiave |

## 3. Tabelle create (migrazioni Flyway)

**V002__identity_access.sql**:
- **Organizzazione**: `tenants`, `organizations`, `users` (email `citext` univoca, `password_hash` nullable per OIDC futuro, `status`, `mfa_enabled`).
- **Ruoli**: `roles`, `permissions`, `role_permissions` (catalogo seminato), `user_role_assignments` (ruolo + scope `PLATFORM|TENANT|ORGANIZATION|HOME`).
- **Case**: `homes` (minimale, completata nelle milestone successive).
- **Sessioni e token**: `user_sessions` (per dispositivo: label, user-agent, IP, ultima attività, scadenza assoluta, motivo di revoca), `refresh_tokens` (solo **SHA-256**, catena `replaced_by`), `user_action_tokens` (verifica email / reset, solo hash, monouso).
- **Protezione**: `auth_throttle` (contatori per account con email hashata e per IP), `audit_logs` (append-only tramite trigger + `REVOKE UPDATE, DELETE`).

**V003__agent_authentication.sql**: `agent_enrollment_tokens` (hash, scadenza, monouso), `agents` (identità univoca legata a `(tenant_id, home_id)`), `agent_credentials` (chiave pubblica Ed25519 univoca, una sola `ACTIVE` per agent, storico `ROTATED/REVOKED`), `agent_assertion_jti` (anti-replay), `agent_access_tokens` (hash, 10 min).

**Isolamento**: RLS `tenant_id = current_tenant_id()` su **ogni** tabella tenant. Le ricerche pre-autenticazione (email al login, hash di token) passano da funzioni `SECURITY DEFINER` che restituiscono solo il `tenant_id`, senza dati: `auth_lookup_user`, `lookup_tenant_by_secret`, `agent_lookup_tenant`. Non sono eseguibili da `PUBLIC`. `purge_expired_auth_data` è la pulizia oraria.

## 4. Flussi

### Login e refresh
1. All'avvio la SPA chiama `GET /auth/csrf` (se manca il cookie) e poi `POST /auth/refresh`. Se il cookie refresh è valido, la sessione viene ripristinata senza credenziali.
2. `POST /auth/login`:
   - controlla il throttle per account e per IP;
   - recupera l'utente tramite la funzione `SECURITY DEFINER`;
   - verifica la password Argon2id (con verifica fittizia per le email inesistenti, così i tempi sono uguali);
   - crea `user_sessions` + `refresh_tokens` (hash);
   - imposta il cookie `shsc_rt` (`HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth`);
   - restituisce un JWT ES256 di 15 min con `sub, tid, sid, roles, jti`.
3. Ogni richiesta API carica dal DB lo stato della sessione, dell'utente e delle assegnazioni di ruolo. Revoche e cambi di ruolo valgono **subito**, senza aspettare la scadenza del JWT.
4. Su 401 l'interceptor esegue **un** refresh:
   - single-flight nella scheda, serializzato tra schede con `navigator.locks`;
   - poi ripete la richiesta originale; se il refresh fallisce, porta a `/login?expired=1`.
5. `POST /auth/refresh` ruota il refresh token: il vecchio diventa `ROTATED` e ne viene emesso uno nuovo. Se si presenta un token **già ruotato o revocato**, la sessione intera viene revocata (`TOKEN_REUSE`) e l'evento `REFRESH_TOKEN_REUSE` va in audit.
6. Durata: refresh `SHSC_REFRESH_TOKEN_TTL` (default 14 giorni, configurabile 7–30), con un tetto assoluto della sessione `SHSC_SESSION_MAX_LIFETIME` (30 giorni).

### Enrollment agent
1. L'utente con `agent:enroll` sulla casa genera un token `shsc_enr_…`: valido 30 min, monouso, mostrato una sola volta, salvato solo come hash.
2. Sul PC: `shsc-agent enroll --api https://… --token-file token.txt [--ca-file dev.pem]`.
   - L'agent genera una chiave Ed25519 locale (`agent.key`, PKCS#8 PEM, scrittura atomica) e invia solo la chiave pubblica.
   - Il backend consuma il token, crea `agents` (legato a tenant e casa) e la credenziale `ACTIVE`.
3. Autenticazione: l'agent firma un'asserzione JWS EdDSA con:
   - `iss = sub = agentId`, `aud = shsc-agent-token`;
   - durata ≤ 60 s (tolleranza sull'orologio di 30 s) e `jti` monouso.

   La riceve in cambio un token opaco `shsc_at_` di 10 min.
4. Rotazione (`rotate-key`):
   - la nuova chiave viene prima salvata come `agent.key.next`;
   - la prova è firmata con la nuova chiave (`aud = shsc-agent-rotate`);
   - la vecchia credenziale diventa `ROTATED` e tutti i token agent vengono revocati;
   - se il processo si interrompe, al login successivo l'agent recupera la chiave pendente.
5. Revoca dalla dashboard: agent `REVOKED`, credenziali e token revocati; la richiesta successiva dell'agent riceve `AGENT_REVOKED`.
6. Associazione agent–casa: ogni operazione agent su una casa passa da `AgentPrincipal.requireHome(homeId)`.

## 5. Sicurezza password e brute force
- **Argon2id** (memoria 19 MiB, 2 iterazioni, parallelismo 1; parametri OWASP). L'hash viene aggiornato al login se i parametri cambiano.
- **Policy**: 12–128 caratteri, nessuna password tra le più comuni (lista locale), niente sequenze o ripetizioni banali, niente nome o email nella password. I valori non vengono mai rimandati negli errori.
- **Throttle**:
  - per account (email hashata): dopo 5 errori, blocco progressivo da 1 min fino a 1 h;
  - per IP: 30 errori, poi blocco di 15 min;
  - endpoint che inviano email: quota 10 per finestra per IP e per account;
  - in più, Nginx limita 30 r/min per IP su `/api/v1/auth/`.

  L'IP client viene da `X-Forwarded-For`, che Nginx **sovrascrive** con `$remote_addr`.
- **Messaggi neutri**: registrazione, password dimenticata e reinvio della verifica rispondono sempre 202. Il login non distingue tra email inesistente e password errata.

## 6. Frontend
- Access token **solo in memoria** (signal), mai in localStorage o sessionStorage (c'è un test che lo verifica).
- Refresh token non leggibile da JavaScript (HttpOnly). CSRF double-submit: `XSRF-TOKEN` → header `X-XSRF-TOKEN` (`withXsrfConfiguration`).
- I token monouso (verifica, reset) arrivano nel **fragment** `#token=`, che non viene inviato al server né nel Referer. Vengono rimossi dalla cronologia subito dopo la lettura.
- `returnUrl` accetta solo percorsi interni (nessun open redirect).
- Pagine: login, registrazione, verifica email, password dimenticata, reset, account (cambio password, sessioni, revoca), case, dettaglio casa (token di enrollment, agent, revoca).

## 7. Configurazione (solo variabili d'ambiente)
`SHSC_JWT_PRIVATE_KEY` (generata con `infrastructure/scripts/generate-jwt-key.sh`), `SHSC_PUBLIC_BASE_URL`, `SHSC_MAIL_FROM`, `SHSC_SMTP_*`, `SHSC_COOKIE_SECURE`, `SHSC_CORS_ALLOWED_ORIGINS` (vuoto = solo same-origin), `SHSC_ACCESS_TOKEN_TTL`, `SHSC_REFRESH_TOKEN_TTL`, `SHSC_SESSION_MAX_LIFETIME`. Nessun segreto nel codice: i test generano chiavi proprie a ogni esecuzione.

## 8. Test di sicurezza
| Suite | Cosa verifica |
|---|---|
| `AuthenticationFlowTest` (8) | login impossibile prima della verifica email; cookie refresh `HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth`; rotazione refresh e rilevamento del riuso; logout che revoca la sessione e cancella il cookie; refresh senza cookie rifiutato; registrazione B2B (crea ORGANIZATION_ADMIN, nome organizzazione obbligatorio); audit di login e logout |
| `AuthenticationSecurityTest` (16) | risposte identiche per email esistenti e inesistenti (login, registrazione, password dimenticata); blocco progressivo dell'account; throttle anche su email inesistenti; un IP non può provare molti account; CSRF obbligatorio e double-submit; cookie CSRF `Secure`/`SameSite=Strict`; **le richieste Bearer non cancellano il cookie CSRF**; policy password; nessuna eco della password negli errori; reset e cambio password che revocano le sessioni; sessioni per dispositivo; impossibile revocare sessioni altrui; JWT manomessi o con `alg: none` rifiutati |
| `TenantIsolationAndRbacTest` (9) | casa di un altro tenant invisibile (404); RLS che nasconde le righe di altri tenant anche senza `WHERE`; audit append-only e per tenant; READ_ONLY legge ma non scrive; tecnico con scope HOME vede solo la propria casa; cambi di ruolo immediati e in audit; nessuna escalation di privilegi; ultimo ORGANIZATION_ADMIN non rimovibile; ruoli di piattaforma nascosti dal catalogo |
| `AgentAuthenticationTest` (9) | token di enrollment monouso e mostrato una volta; token scaduti o revocati rifiutati; chiavi pubbliche non valide rifiutate; asserzione firmata → token breve legato alla casa; asserzioni riusate, contraffatte o troppo lunghe rifiutate; credenziali utente e agent non intercambiabili; agent revocato bloccato subito; rotazione che ritira la vecchia chiave; agent di altri tenant non gestibili |
| `AccessTokenValidationTest` (1) | token firmati con la **vera** chiave del server ma con un solo claim errato vengono rifiutati: scaduto, altro issuer, altra audience, `token_use=refresh`, `sid` o `tid` mancanti, sessione inesistente, tenant diverso. Rifiutato anche un token firmato da un'altra chiave P-256 con lo stesso `kid`. Un token di controllo corretto viene accettato |
| `PasswordPolicyTest` (3), `JwtKeysTest` (2) | policy, derivazione della chiave pubblica e kid |
| `DatabaseBaselineTest` (9) | migrazioni 001–003; RLS attiva su **tutte** le tabelle tenant; funzioni `SECURITY DEFINER` non eseguibili da PUBLIC; ruolo app senza BYPASSRLS |
| `HttpSurfaceTest` (9) | API non autenticate → 401 problem+json; `Cache-Control: no-store`; nessun permesso CORS a origini estranee |
| Frontend (51) | token solo in memoria, refresh single-flight, interceptor (Bearer solo su `/api/`, mai sugli endpoint cookie, un solo retry, nessun refresh su 403), guard e anti open-redirect, pagine di login, registrazione, verifica e account; date nella lingua scelta; revoca agent con conferma; lista case vuota coerente con i permessi |
| Agent Go (19, `-race`) | asserzione EdDSA, enrollment, login, recupero della chiave pendente, rotazione, CLI, solo HTTPS |

**Verifica end-to-end** sullo stack Docker (`https://localhost:8443`, Mailpit):
- flusso utente completo via HTTPS: link reale da Mailpit, login senza CSRF → 403, rotazione e riuso del refresh → sessione revocata, logout, reset;
- binario Windows reale dell'agent: certificato non attendibile rifiutato senza `--ca-file`, enrollment, token riusato rifiutato, status, rotazione della chiave, revoca dalla dashboard → agent respinto;
- eventi presenti in audit.

### 8.1 Verifica dell'interfaccia nel browser
**Ambiente.** Browser integrato collegato a un nginx temporaneo in HTTP su `127.0.0.1:8090`. Usa la stessa immagine e la stessa build Angular e inoltra al backend reale. Il browser integrato non accetta il certificato self-signed. La configurazione temporanea non fa parte del repository.

**Account e metodo.**
- Account di prova creati per il test:
  - organizzazione A con un admin (registrato dall'interfaccia), un tecnico con scope sulla casa "Casa Rossi", un utente in sola lettura e un utente senza ruoli;
  - organizzazione B con un admin;
  - un privato (CUSTOMER).
- I ruoli sono stati assegnati via API. Gli utenti aggiuntivi di A sono stati inseriti nel DB, perché l'API di invito non fa parte della M3.
- Per vedere il refresh automatico senza aspettare 15 minuti, il backend è stato riavviato temporaneamente con `SHSC_ACCESS_TOKEN_TTL=PT1M` e poi riportato a `PT15M`.

| # | Area | Verifica | Esito |
|---|---|---|---|
| 1 | Login | login prima della verifica email → "Devi prima confermare il tuo indirizzo email"; link reale da Mailpit → email confermata, token tolto dall'URL; password errata → messaggio generico e campo password svuotato; login corretto → redirect al `returnUrl` (`/account`); `localStorage`/`sessionStorage` vuoti, cookie di refresh non visibile a JavaScript | ✅ |
| 2 | Refresh e scadenza | dopo il ricaricamento la sessione viene ripristinata (refresh 200); con l'access token scaduto la richiesta riceve 401 → refresh 200 → richiesta ripetuta 200, senza intervento dell'utente; sessione revocata da un altro dispositivo → refresh 401 → `/login?expired=1` "La sessione è scaduta" | ✅ |
| 3 | Logout | "Esci" → `/login`; refresh successivo 401 `INVALID_REFRESH_TOKEN`; sessione revocata nel DB (motivo `LOGOUT`) | ✅ |
| 4 | Pagine protette | `/homes` senza sessione → `/login?returnUrl=%2Fhomes`; dopo il logout tornare a `/homes` → di nuovo il login | ✅ |
| 5 | Ruoli | admin: crea case, genera codici, revoca; tecnico (scope HOME): vede solo la sua casa, nessun form "Nuova abitazione", l'altra casa da URL → "Elemento non trovato" (404); sola lettura: vede tutte le case, nessun pulsante; utente senza ruoli: solo "Non hai i permessi"; via API: scritture di READ_ONLY → 403, auto-promozione del tecnico → 403, admin che assegna SUPER_ADMIN → 403 | ✅ |
| 6 | Isolamento | admin B: vede solo le proprie case; casa di A da URL → "Elemento non trovato"; via API ogni risorsa di A (casa, agent, codici, ruoli di utenti di A, revoca) → 404; assegnare a sé uno scope su una casa di A dà la stessa risposta di una casa inesistente (`INVALID_SCOPE`); il CUSTOMER privato non vede nulla di A; l'audit di A non contiene eventi di B | ✅ |
| 7 | Agent | codice generato dal tecnico e mostrato una volta; enrollment del binario Windows reale via HTTPS; codice riusato rifiutato; stato "Attivo" e codice "Usato" in pagina; rotazione della chiave; revoca dall'interfaccia (ora con conferma) → `status` e `rotate-key` rifiutati subito | ✅ |

**Console e rete.**
- Nessuna eccezione JavaScript. In console ci sono solo i messaggi "Failed to load resource" che il browser scrive per ogni risposta 4xx.
- Tutti i 4xx osservati sono attesi:
  - 401 sul refresh all'apertura senza sessione (tentativo di ripristino);
  - 401 su access token scaduto, seguito dal refresh;
  - 403 e 401 sul login nei casi di prova;
  - 403 per l'utente senza ruoli;
  - 404 sulle risorse di un'altra organizzazione.
- Nessuna risposta 5xx.

**Problemi trovati e corretti.**
1. Date sempre in formato inglese: ora la pipe `appDate` segue la lingua.
2. Revoca dell'agent irreversibile con un solo clic: ora c'è una conferma in due passaggi.
3. Messaggi contraddittori nella lista case vuota per chi non ha permessi.

Ogni correzione è coperta da test (`localized-date.pipe.spec.ts`, `homes.page.spec.ts`, `home-detail.page.spec.ts`) ed è stata ricontrollata nel browser.

## 9. Limiti noti
- MFA (TOTP) e login OIDC sono predisposti ma **non implementati** in questa milestone.
- Su Windows i permessi `0600` dei file dell'agent non si applicano: il file eredita le ACL della cartella. La cartella di default `C:\ProgramData\SHSC\agent` andrà protetta con ACL dedicate dall'installer o servizio (milestone agent).
- La lista delle password comuni è locale (nessun servizio esterno). Have I Been Pwned (k-anonymity, gratuito) è un'opzione futura da approvare.
- Il throttling è salvato in PostgreSQL (`auth_throttle`), quindi resta coerente anche con più istanze del backend; il costo è una scrittura in DB per ogni tentativo fallito.
- La verifica nel browser (§8.1) è passata da HTTP locale invece che da HTTPS. Il pannello del browser era nascosto, quindi le azioni sono state eseguite come eventi DOM e non come clic del mouse, e il rendering visivo (screenshot) non è stato controllato.
- I tentativi di assegnazione di ruolo rifiutati (403) non vengono registrati nell'audit; vengono registrati solo i cambi riusciti.
- All'apertura dell'app senza sessione la console mostra un 401 del tentativo di ripristino. È il comportamento previsto: il cookie HttpOnly non è leggibile, quindi l'unico modo per sapere se c'è una sessione è chiedere al server.
