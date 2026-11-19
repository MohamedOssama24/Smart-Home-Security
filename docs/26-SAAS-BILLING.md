# 26 — SaaS, Stripe e white label (Milestone 17)

Piani a pagamento con Stripe Checkout e Billing Portal, stato della sottoscrizione solo da webhook firmati, white label per le organizzazioni. Decisione: ADR-072.

## Piani (`plans`, V015)

| Piano | Chi | Abitazioni | Utenti | Clienti | Reti/casa | Agent/casa | Scansioni/giorno | White label |
|---|---|---|---|---|---|---|---|---|
| `FREE` | tutti | 2 | 3 | 2 | 4 | 2 | 10 | no |
| `PLUS` | INDIVIDUAL | 5 | 6 | 0 | 6 | 3 | 30 | no |
| `PRO` | BUSINESS | 50 | 20 | 50 | 8 | 5 | 50 | sì |

I prezzi esistono solo in Stripe: `SHSC_STRIPE_PRICE_PLUS` e `SHSC_STRIPE_PRICE_PRO` sono i Price id. Un piano senza Price configurato non è acquistabile. I limiti sono applicati da `PlanLimits` come per FREE.

## Configurazione

| Variabile | Note |
|---|---|
| `SHSC_STRIPE_SECRET_KEY` | `sk_test_…` o `rk_test_…` (chiave limitata: Customers, Checkout Sessions, Billing Portal in scrittura; Subscriptions in lettura dalla M18). Vuota = abbonamenti online disattivati |
| `SHSC_STRIPE_WEBHOOK_SECRET` | `whsec_…` dell'endpoint `https://<host>/api/v1/billing/stripe/webhook` |
| `SHSC_STRIPE_PRICE_PLUS`, `SHSC_STRIPE_PRICE_PRO` | Price ricorrenti |
| `SHSC_STRIPE_ALLOW_LIVE` | `false` di default: le chiavi live sono rifiutate all'avvio, gli eventi `livemode` ignorati |
| `SHSC_STRIPE_TRIAL_DAYS` | Giorni di prova gratuita al checkout, una sola volta per tenant. `0` (predefinito) = nessuna prova, massimo 730. Fuori intervallo: errore all'avvio |

In Stripe: eventi webhook `checkout.session.completed` e `customer.subscription.created|updated|deleted`. Nel Billing Portal, se si abilita il cambio piano, vanno ammessi solo i Price configurati.

## Flusso

1. `POST /billing/checkout {planCode}`: `billing:manage` a livello tenant. Il piano deve essere ammesso per il tipo di tenant, e non deve esistere già una sottoscrizione non terminata (409 `SUBSCRIPTION_EXISTS`). Alla prima volta crea il cliente Stripe (`Idempotency-Key` = tenant) e lo salva in `tenant_subscriptions`, poi crea la Checkout Session (`mode=subscription`, ritorno su `/billing?checkout=success|cancel`).
   **Doppio checkout (M18)**: i checkout dello stesso tenant sono serializzati dal lock sulla riga di `tenant_subscriptions`. Prima di creare la sessione si chiede a Stripe se il customer ha già una sottoscrizione non terminata (anche se il webhook non è ancora arrivato: 409 `SUBSCRIPTION_EXISTS`) e si fanno scadere le sessioni ancora aperte. Così solo l'ultima sessione può essere pagata.
2. Il browser va su Stripe; la dashboard segue solo URL `https://checkout.stripe.com` / `billing.stripe.com`.
3. Stripe invia i webhook, gestiti nell'ordine seguente.
   1. Verifica della firma sul corpo grezzo (≤ 256 KB, tolleranza 5 min). Se fallisce: 400.
   2. Validazione degli id dell'evento.
   3. Tenant ricavato dal `customer` con `billing_lookup_tenant`; un customer sconosciuto dà `IGNORED`.
   4. Elaborazione in una transazione del tenant: lock della riga della sottoscrizione, poi verifica che l'evento non sia già stato elaborato (altrimenti `DUPLICATE`).
   5. `checkout.session.completed` collega la sottoscrizione. `customer.subscription.*` aggiorna stato, piano (dal Price), fine periodo e disdetta.
   6. Un evento più vecchio dell'ultimo applicato dà `STALE`. Un evento terminale di un'altra sottoscrizione dà `IGNORED`. Una seconda sottoscrizione mentre quella corrente non è terminata non la sostituisce mai: `IGNORED`, log di errore e audit `SUBSCRIPTION_CHANGED` con `duplicate=true`, da annullare a mano in Stripe.
   7. Piano effettivo: piano del Price se lo stato è `active`, `trialing` o `past_due` e il piano è ammesso per il tipo di tenant; altrimenti `FREE`. Audit `SUBSCRIPTION_CHANGED`.
4. `POST /billing/portal`: cambio piano, metodo di pagamento, fatture, disdetta.

## Prova gratuita (V016)

- **Offerta**: `GET /billing` restituisce `trialDays` (`0` se la prova è disattivata o già usata). La prova è offerta finché il tenant non ha avuto una sottoscrizione Stripe: un checkout abbandonato non la consuma. `trial_used` diventa vero al primo evento di sottoscrizione.
- **Checkout con prova**: `subscription_data[trial_period_days]=N`, `payment_method_collection=always` (la carta è raccolta subito, nessun addebito fino alla fine della prova) e `trial_settings.end_behavior.missing_payment_method=cancel`.
- **Durante la prova**: stato `trialing`, si applica il piano acquistato. `subscription.trialEnd` mostra la fine della prova.
- **Fine della prova**, decisa dai webhook di Stripe:
  - pagamento riuscito → `active`: resta il piano a pagamento;
  - primo pagamento fallito → `past_due`: si applica subito `FREE`, perché la sottoscrizione non è mai stata pagata (`has_paid` falso). Se Stripe incassa un nuovo tentativo → `active` e il piano torna;
  - tentativi esauriti o nessun metodo di pagamento → `canceled`/`unpaid` → `FREE`.
- **`past_due` dopo almeno un pagamento**: resta il periodo di tolleranza con il piano a pagamento, come prima. `has_paid` vale per la sottoscrizione corrente e si azzera con una nuova.
- **Downgrade**: nessun dato viene cancellato. Abitazioni, utenti, clienti, reti e agent oltre i limiti restano; i limiti del nuovo piano valgono per le operazioni successive (creazioni, scansioni giornaliere), con 409 `PLAN_LIMIT_REACHED`.

## Separazione tra tenant

- `tenant_subscriptions` e `tenant_branding` hanno RLS; i Stripe id non vengono mai restituiti dalle API.
- Il webhook non usa metadati né `client_reference_id`: un evento modifica solo il tenant che possiede quel customer.
- `stripe_webhook_events` (RLS per tenant dalla M18, migrazione V017) contiene solo id, tipo, tenant ed esito; il ruolo runtime non può modificarlo né cancellarlo.

## White label

`PUT /branding` (nome ≤ 80 senza caratteri di controllo, colore `#rrggbb`, e-mail di supporto) e `PUT /branding/logo` (PNG o JPEG, ≤ 256 KB, ≤ 2048×2048, magic bytes coerenti, niente SVG). Le modifiche richiedono `organization:manage` a livello tenant e un piano con white label. Applicato a:
- header della dashboard: nome, colore `--primary`, logo come data URL;
- report PDF: nome in testa e come creator.

Con un piano senza white label i dati restano ma `GET /branding` risponde `available=false` e il logo 404.

## Test

- `BillingIntegrationTest` (server Stripe simulato [MOCK]):
  - piani per tipo di tenant;
  - firma errata, scaduta o manomessa;
  - evento applicato una volta, replay `DUPLICATE`;
  - una sola sottoscrizione; portale;
  - `STALE` e customer sconosciuto;
  - due organizzazioni e metadati falsificati; piano di un altro tipo non applicato;
  - white label solo PRO, con validazione del logo; permessi TECHNICIAN e READ_ONLY;
  - disdetta che riporta a FREE;
  - doppio checkout (M18): 5 checkout paralleli lasciano una sola sessione aperta, sottoscrizione già in Stripe → 409, seconda sottoscrizione mai applicata;
  - prova gratuita: parametri del checkout, prova non consumata da un checkout abbandonato, `trialing` → `active` (piano mantenuto), `trialing` → `past_due` (FREE, dati conservati, nuova abitazione rifiutata) → `active` (piano ripristinato) → `canceled` (FREE), nessuna seconda prova.
- `StripeWebhookVerifierTest`: rotazione del segreto (più `v1`), tolleranza, intestazioni malformate.
- `ReportRendererTest`: brand nel PDF.
- `billing.page.spec.ts`: checkout con l'offerta di prova, redirect solo verso Stripe, errori.

## Limiti

- Non provato con un account Stripe reale (prova in test mode nella M18); nessun `GET /payments` né area `/admin/**`.
- Un solo Price per piano (niente mensile/annuale, quantità o consumo).
- Profili DEEP/CUSTOM legati al piano non implementati.
- White label non applicato a e-mail e app mobile.
- Nessuna retention per `stripe_webhook_events`.
