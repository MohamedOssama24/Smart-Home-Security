# 06 — Autenticazione, autorizzazione, multi-tenancy, sicurezza piattaforma

## 1. Autenticazione utenti
| Elemento | Scelta |
|---|---|
| Hash password | **Argon2id** (Spring Security `Argon2PasswordEncoder`, parametri OWASP: m=19 MiB, t=2, p=1), politica lunghezza ≥ 12 + controllo password note compromesse (lista locale, nessuna chiamata esterna) |
| Access token | JWT **ES256**, 10 min, claim `sub`, `tid` (tenant), `roles`, `perm_ver`; firmato con chiave da secret, `kid` per rotazione, JWKS interno |
| Refresh token | opaco 256 bit, salvato come SHA-256, 14 gg (30 con "ricordami"), **rotazione a ogni uso**; riuso di un token già ruotato ⇒ revoca dell'intera famiglia + alert sicurezza |
| Trasporto web | access token **in memoria** (mai localStorage); refresh in cookie `HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth` |
| CSRF | richiesto solo sulle rotte che usano il cookie (`/auth/refresh`, `/auth/logout`): SameSite=Strict + double-submit token header. Le altre API usano Bearer → non vulnerabili a CSRF |
| Mobile | refresh token in `flutter_secure_storage` (Keychain/Keystore), inviato nel body |
| MFA | **TOTP** (RFC 6238) + 10 recovery code monouso; obbligatoria per SUPER_ADMIN e ORG_ADMIN, opzionale per gli altri. WebAuthn/passkey in roadmap |
| Account | verifica email, lockout progressivo, notifica nuovo login, reset password con token monouso 30 min |

## 2. Modello multi-tenant
```
Tenant (isolamento + abbonamento)
 ├── INDIVIDUAL (B2C):  utenti ─► homes ─► networks/agents/devices
 └── BUSINESS (B2B):    organization ─► customers ─► homes ─► networks/agents/devices
                        utenti dell'organizzazione (ORG_ADMIN, TECHNICIAN, READ_ONLY)
                        utenti dei clienti (CUSTOMER) limitati alle homes del proprio customer
```
- Strategia: **database condiviso, schema condiviso, colonna `tenant_id` + RLS** (vedi `04-DATABASE.md §3`). È la soluzione più economica e scalabile per migliaia di tenant piccoli; schema-per-tenant valutato e scartato (migrazioni N volte, pool di connessioni).
- Un cliente finale di un installatore può in futuro "staccarsi" e diventare tenant B2C: previsto un processo di migrazione dati (non MVP).

## 3. RBAC
| Ruolo | Ambito | Capacità principali |
|---|---|---|
| SUPER_ADMIN | piattaforma | amministrazione, supporto (accesso ai tenant solo con motivazione registrata, "break-glass") |
| ORG_ADMIN | tenant | tutto nel tenant: utenti, clienti, homes, agent, billing |
| TECHNICIAN | tenant o clienti assegnati | homes, agent, scansioni, classificazione, finding, report; no billing/utenti |
| CUSTOMER | proprie homes (B2C: proprietario; B2B: homes del proprio customer) | scansioni manuali, consultazione, preferenze; in B2C anche billing |
| READ_ONLY | ambito assegnato | sola lettura |

Permessi fini (`home:read`, `home:write`, `scan:create`, `scan:cancel`, `device:classify`, `finding:triage`, `agent:enroll`, `agent:revoke`, `report:generate`, `billing:manage`, `user:manage`, `integration:manage`…). Valutazione: `permesso del ruolo ∧ risorsa nello scope dell'assegnazione ∧ risorsa del tenant`.

## 4. Sicurezza della piattaforma — checklist di controlli
| Minaccia | Controllo |
|---|---|
| Intercettazione | HTTPS ovunque, HSTS, TLS 1.2+ (Nginx), cookie Secure |
| SQL injection | solo query parametrizzate (JPA/JDBC), nessuna concatenazione; test dedicati |
| XSS | Angular escaping di default, nessun `bypassSecurityTrust*`, CSP restrittiva, i dati dai dispositivi (hostname, SSDP friendlyName, banner) sono **input ostile** e sempre trattati come testo |
| CSRF | vedi §1 |
| Broken access control | RBAC + scope + RLS + 404 su risorse di altri tenant; test di isolamento |
| Brute force login | rate limit + lockout + MFA |
| Abuso API agent | firma, anti-replay `jti`, validazione scope IP, limiti dimensione |
| Segreti | solo env/Docker secrets; `.env` ignorato da git; segreti a riposo (TOTP, credenziali integrazioni server-side) cifrati AES-256-GCM con chiave dedicata; scanning segreti in CI (gitleaks) |
| Supply chain | lockfile, Dependabot/Renovate, OWASP dependency-check / `govulncheck` / `npm audit` in CI, build riproducibili agent, update firmati |
| Audit | `audit_logs` per login, cambi ruolo, enrollment/revoca agent, scansioni, autorizzazione reti, classificazioni manuali, triage finding, accessi super admin |
| Backup | pg_dump cifrato giornaliero + retention, test di restore periodico |
| Privacy (GDPR) | IP/MAC/hostname = dati personali: minimizzazione, retention, export/cancellazione account, DPA per clienti B2B, hosting UE |

## 5. Limiti etici e legali delle scansioni (vincolanti nel codice)
1. Scansione solo di **reti autorizzate** confermate esplicitamente dall'utente, verificate **sia dal backend sia dall'agent**.
2. L'agent rifiuta qualsiasi target fuori da: sottoreti direttamente connesse ∩ reti autorizzate ∩ intervalli privati (RFC 1918, link-local, IPv6 ULA/link-local). IP pubblici e CGNAT (100.64.0.0/10) sempre esclusi.
3. Limite dimensione: /22 (1024 host) per default; oltre richiede configurazione esplicita.
4. **Mai**: exploit, payload distruttivi, brute force, credenziali predefinite, login anonimi (FTP anonymous, SNMP `public`), DoS, raccolta di immagini/video/stream dalle telecamere (RTSP solo `OPTIONS`, mai `DESCRIBE`/`PLAY`).
5. Rate limit e concorrenza conservativi per non disturbare dispositivi IoT fragili.
