# 04 — Progettazione database (PostgreSQL 18)

## 1. Convenzioni
- PK `uuid` **UUIDv7** (ordinabile nel tempo; `uuidv7()` nativo in PG18, generato anche lato app).
- Ogni tabella tenant-scoped ha `tenant_id uuid NOT NULL` + FK + indice, e una **policy RLS** (§3).
- `created_at`, `updated_at timestamptz` ovunque; `version bigint` per optimistic locking sulle entità mutabili.
- Enum come `text` + `CHECK` (più semplici da migrare degli enum PG).
- Dati semi-strutturati (evidenze, payload grezzi) in `jsonb`; tutto ciò che viene filtrato/aggregato è in colonne.
- Migrazioni **Flyway** in `database/migrations/V<NNN>__<descrizione>.sql`, copiate nel classpath in build. Mai modificare una migrazione già applicata.
- Soft delete solo dove serve (homes, devices: `archived_at`); gli audit log sono append-only.

## 2. Schema logico

### Identità, tenancy, RBAC
| Tabella | Colonne principali | Note |
|---|---|---|
| `tenants` | id, type (`INDIVIDUAL`/`BUSINESS`), name, status, plan_id, white_label jsonb | radice di isolamento e fatturazione |
| `organizations` | id, tenant_id, legal_name, vat_number, contact, branding | 1:1 con tenant BUSINESS (B2B) |
| `customers` | id, tenant_id, organization_id, display_name, contact | clienti gestiti da un'organizzazione B2B |
| `users` | id, email (citext, unique globale), password_hash (Argon2id), status, locale, email_verified_at, mfa_enabled, failed_logins, locked_until | un utente appartiene a un tenant |
| `tenant_memberships` | user_id, tenant_id, status | predisposto per utenti multi-tenant (tecnici) |
| `roles` | id, code (`SUPER_ADMIN`,`ORG_ADMIN`,`TECHNICIAN`,`CUSTOMER`,`READ_ONLY`), system bool | |
| `permissions` | id, code (es. `scan:create`, `device:classify`, `agent:revoke`) | |
| `role_permissions` | role_id, permission_id | |
| `user_roles` | user_id, role_id, tenant_id, scope_type (`TENANT`/`CUSTOMER`/`HOME`), scope_id | ruolo con ambito |
| `refresh_tokens` | id, user_id, family_id, token_hash, expires_at, used_at, revoked_at, ip, user_agent | rotation + reuse detection |
| `mfa_credentials` | id, user_id, type (`TOTP`), secret_encrypted, recovery_codes_hash[] | segreto cifrato AES-GCM con chiave da env |
| `audit_logs` | id, tenant_id (nullable per piattaforma), actor_user_id/agent_id, action, target_type, target_id, ip, details jsonb, at | append-only, partizionata per mese |

> **Implementato in Milestone 4** (`V004__organizations_customers_networks.sql`, dettagli in [13-USERS-ORGANIZATIONS-NETWORKS.md](13-USERS-ORGANIZATIONS-NETWORKS.md)):
> - `plans`: limiti in colonne esplicite (`max_homes`, `max_users`, `max_customers`, `max_networks_per_home`); `tenants.plan_code`, default `FREE`.
> - `organizations`: aggiunti `vat_number`, `contact_email`, `contact_phone`.
> - `customers`: archiviati con `archived_at`.
> - `homes`: aggiunti `customer_id`, `address`, `timezone`.
> - `networks`: vincoli `CHECK` su intervallo privato e dimensione; `source = MANUAL`.
> - `network_authorizations`: corrisponde a `authorized_networks` qui sotto. Conserva lo storico, con al massimo un'autorizzazione attiva per rete.
> - Nuovo ambito di ruolo `CUSTOMER` e scopo `INVITATION` per i token monouso.
> - `gateway` e `interface_name` delle reti arriveranno con le reti rilevate dall'agent.

### Abitazioni, reti, agent
| Tabella | Colonne principali | Note |
|---|---|---|
| `homes` | id, tenant_id, customer_id (null per B2C), name, address, timezone | |
| `networks` | id, tenant_id, home_id, cidr (`cidr`), ip_version, gateway, interface_name, kind (`ETHERNET`,`WIFI`,`VLAN`,`GUEST`,`UNKNOWN`) | rilevate dall'agent |
| `authorized_networks` | id, tenant_id, network_id, authorized_by, authorized_at, attestation_text_version, revoked_at | **solo qui si può scansionare** |
| `agents` | id, tenant_id, home_id, name, os, arch, version, status, capabilities jsonb, last_heartbeat_at | |
| `agent_credentials` | id, agent_id, public_key, algorithm, status (`ACTIVE`/`ROTATING`/`REVOKED`), created_at, revoked_at, revoked_by, reason | |
| `agent_enrollment_tokens` | id, tenant_id, home_id, token_hash, expires_at, used_at, created_by, revoked_at | monouso |
| `agent_events` | id, tenant_id, agent_id, type, payload jsonb, at | heartbeat anomali, errori, update — partizionata |
| `agent_token_jti` | jti, agent_id, expires_at | anti-replay asserzioni |

### Scansioni
| Tabella | Colonne principali | Note |
|---|---|---|
| `scans` | id, tenant_id, home_id, agent_id, trigger (`CHECK = 'MANUAL'` nell'MVP), profile, status, requested_by, requested_at, queued_at, started_at, completed_at, lease_expires_at, cancel_requested_at, progress jsonb, devices_discovered, devices_analyzed, devices_not_analyzable, coverage numeric, failure_reason, idempotency_key, analysis_version, version | indice unico parziale `(home_id) WHERE status IN ('PENDING','QUEUED','RUNNING')` |
| `scan_targets` | id, scan_id, type (`ALL_AUTHORIZED`/`DEVICE`/`IP`), network_id, device_id, ip | |
| `scan_events` | id, scan_id, from_status, to_status, actor, reason, at | storico transizioni |
| `scan_results` | id, scan_id, batch_seq, received_at, payload_sha256, observation_count, raw jsonb (compresso, retention 90 gg) | idempotenza `(scan_id, batch_seq)` unique |

### Inventario e fingerprinting
| Tabella | Colonne principali | Note |
|---|---|---|
| `devices` | id, tenant_id, home_id, network_id, mac, mac_randomized bool, current_ip, hostname, manufacturer, model, os_name, os_version, firmware_version, detected_category, detected_category_confidence, manual_category, manual_category_by, manual_category_at, display_name, overall_confidence, first_seen_at, last_seen_at, last_scan_id, is_mock bool, archived_at | identità: `(home_id, mac)` unique quando mac non null |
| `device_observations` | id, tenant_id, device_id, scan_id, ip, mac, method (`ARP`,`ICMP`,`MDNS`,`SSDP`,`ROUTER`,`DHCP`,`NETBIOS`,`RDNS`), interface, raw jsonb, observed_at | partizionata per mese |
| `device_identifications` | id, device_id, scan_id, field (`IP`,`MAC`,`MANUFACTURER`,`HOSTNAME`,`DEVICE_TYPE`,`MODEL`,`OS`,`FIRMWARE`), value, confidence (`HIGH`/`MEDIUM`/`LOW`), sources jsonb, method, ruleset_version | **confidenza per campo** |
| `device_category_changes` | id, device_id, old_category, new_category, source (`AUTO`/`MANUAL`), changed_by, changed_at | storico correzioni |
| `open_ports` | id, tenant_id, device_id, scan_id, protocol (`TCP`/`UDP`), port, state (`OPEN`,`CLOSED`,`FILTERED`,`OPEN_FILTERED`,`UNKNOWN`), reason, first_seen_at, last_seen_at | unique `(scan_id, device_id, protocol, port)` |
| `detected_services` | id, open_port_id, name, product, version, status (`PROBABLE`/`CONFIRMED`), confidence, evidence jsonb, tls jsonb | |
| `detected_protocols` | id, device_id, scan_id, protocol (`MDNS`,`SSDP`,`UPNP`,`ONVIF`,`MQTT`,`RTSP`,`SMB`,`SNMP`,`COAP`…), details jsonb, confidence | |
| `oui_entries` | prefix, prefix_length (24/28/36), organization, registry, updated_at | da registri IEEE |

### Sicurezza e rischio
| Tabella | Colonne principali | Note |
|---|---|---|
| `findings` | id, tenant_id, home_id, device_id, rule_id, fingerprint (hash dedup), title_key, description_key, params jsonb, severity, finding_type (`CONFIRMED_VULNERABILITY`,`POTENTIAL_RISK`,`SUSPICIOUS_CONFIGURATION`,`UNVERIFIED_INFORMATION`), confidence, source, status (`OPEN`,`ACKNOWLEDGED`,`RESOLVED`,`FALSE_POSITIVE`,`ACCEPTED_RISK`), first_detected_at, last_detected_at, resolved_at, first_scan_id, last_scan_id, recommendation_key | testi via chiavi i18n |
| `finding_evidence` | id, finding_id, scan_id, type, data jsonb, collected_at | |
| `vulnerabilities` | id (CVE), published_at, modified_at, description, cvss_version, cvss_score, cvss_vector, severity, cwe[], kev bool, kev_date_added, kev_due_date, epss_score, references jsonb, source, synced_at | mirror globale (non tenant) |
| `vulnerability_cpe_matches` | id, cve_id, cpe23, version_start_incl/excl, version_end_incl/excl, vulnerable bool | |
| `device_vulnerabilities` | id, tenant_id, device_id, cve_id, finding_id, match_quality (`EXACT_VERSION`,`VERSION_RANGE`,`PRODUCT_ONLY`), matched_cpe, status | `PRODUCT_ONLY` → mai "confermata" |
| `risk_snapshots` | id, tenant_id, home_id, scan_id, score, risk_level, coverage, provisional bool, breakdown jsonb, top_devices jsonb, delta_from_previous, computed_at, engine_version | spiegabilità |

### Notifiche, report, integrazioni, SaaS
| Tabella | Colonne principali |
|---|---|
| `alerts` | id, tenant_id, home_id, device_id, type, severity, dedup_key, occurrences, first_at, last_at, read_at, resolved_at, payload jsonb |
| `alert_deliveries` | id, alert_id, channel (`DASHBOARD`,`EMAIL`,`PUSH`), user_id, status, attempts, sent_at, error |
| `notification_preferences` | id, user_id, tenant_id, alert_type, channel, enabled, min_severity, quiet_hours |
| `push_devices` | id, user_id, platform, fcm_token_encrypted, last_seen_at |
| `reports` | id, tenant_id, home_id, scan_id, locale, status, storage_key, sha256, generated_by, generated_at |
| `integrations` | id, tenant_id, home_id, type (`HOME_ASSISTANT`,`TR064`,`UPNP_IGD`,`SNMP`…), status, config jsonb (mai segreti), secret_location (`AGENT_LOCAL`/`SERVER_ENCRYPTED`) |
| `plans` | id, code (`FREE`,`HOME`,`PROFESSIONAL`,`BUSINESS`), limits jsonb (homes, agents, devices, scans/giorno, profili, report, utenti), stripe_price_ids |
| `subscriptions` | id, tenant_id, plan_id, status (`TRIALING`,`ACTIVE`,`PAST_DUE`,`CANCELED`), stripe_customer_id, stripe_subscription_id, trial_ends_at, current_period_end, cancel_at_period_end |
| `payments` | id, tenant_id, subscription_id, stripe_invoice_id, amount_cents, currency, status, paid_at (nessun dato carta) |
| `stripe_webhook_events` | event_id (PK), type, received_at, processed_at — idempotenza webhook |
| `idempotency_keys` | key, user_id, endpoint, response_hash, created_at |

## 3. Tenant isolation — difesa in profondità
1. **Applicativo**: `TenantContext` impostato dal JWT; tutti i repository passano per servizi che filtrano per `tenant_id`; ArchUnit vieta query su tabelle tenant-scoped fuori dai repository autorizzati.
2. **Database (RLS)**: all'inizio di ogni transazione `SET LOCAL app.tenant_id = '<uuid>'`; policy `USING (tenant_id = current_setting('app.tenant_id')::uuid)`. L'utente DB dell'applicazione **non** è owner delle tabelle e non ha `BYPASSRLS`. Le operazioni di piattaforma (super admin, sync feed) usano un ruolo DB distinto e sono auditate.
3. **Test**: suite dedicata che crea due tenant e verifica che ogni endpoint/repository non restituisca dati dell'altro (anche bypassando lo strato applicativo).

## 4. Indici principali
`devices(tenant_id, home_id, last_seen_at)`, `devices(home_id, mac)` unique parziale, `findings(tenant_id, home_id, status, severity)`, `findings(device_id, fingerprint)` unique, `scans(home_id, requested_at desc)`, `open_ports(device_id, scan_id)`, `vulnerability_cpe_matches(cpe23)` (+ indice trigram/prefisso su vendor:product), `alerts(tenant_id, dedup_key)`, `audit_logs(tenant_id, at)`.

## 5. Retention (configurabile, da confermare)
Raw risultati 90 gg · osservazioni 13 mesi · audit 24 mesi · snapshot rischio illimitati (piccoli).
