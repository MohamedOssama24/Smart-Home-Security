# 28 — Guida utente (Milestone 18)

Guida breve per chi usa Smart Home Security Check: privati (piano FREE/PLUS) e installatori o aziende (FREE/PRO). Dettagli tecnici nei documenti 12–26.

## 1. Account

1. Registrarsi dalla dashboard come **privato** o **organizzazione** e confermare l'e-mail (link valido 24 ore).
2. Usare una password robusta e unica: la verifica in due passaggi non è ancora disponibile.
3. Le organizzazioni invitano i collaboratori via e-mail (link valido 7 giorni) assegnando un ruolo, per esempio tecnico o sola lettura.
4. Da *Account* si gestiscono profilo, password e sessioni attive.

## 2. Abitazioni e reti

- Creare un'**abitazione** (le organizzazioni prima creano il **cliente**).
- Aggiungere le **reti** da analizzare (es. `192.168.1.0/24`). Analizzare solo reti di cui si è proprietari o per cui si ha l'autorizzazione scritta.
- I limiti dipendono dal piano (pagina *Abbonamento*). Se si scende di piano non si perde nulla: si bloccano solo le nuove aggiunte oltre il limite.

## 3. Installare l'agent

L'agent è un piccolo programma che gira su un computer della rete di casa ed esegue le scansioni. Non apre porte in ingresso: contatta solo il server.

1. Scaricare l'agent per il proprio sistema insieme a `SHA256SUMS`, `SHA256SUMS.sig` e `shsc-release-sign`.
2. **Verificare** i file prima di installarli:
   `shsc-release-sign verify release.pub SHA256SUMS` e poi `sha256sum -c SHA256SUMS`. Se la verifica fallisce, non installare.
3. Dalla pagina dell'abitazione generare un **codice di collegamento** (valido 30 minuti, monouso, mostrato una sola volta) e salvarlo in `token.txt`.
4. `shsc-agent enroll --api https://<server> --token-file token.txt`, poi da amministratore `shsc-agent service install`.
5. `shsc-agent diagnose` mostra se l'agent raggiunge il server e quali funzioni ha a disposizione.

Un agent si può revocare in qualsiasi momento dalla dashboard.

## 4. Scansioni

- Dalla pagina della rete: **Avvia scansione** e scegliere il profilo (`QUICK` rapido, `STANDARD` più completo).
- La scansione trova i dispositivi, li classifica, controlla porte e servizi esposti e li confronta con le vulnerabilità note (NVD, catalogo KEV della CISA, EPSS).
- Non vengono mai provate password, attacchi o exploit: l'analisi è solo osservazione.

## 5. Risultati

- **Punteggio di sicurezza 0–100** dell'abitazione e dei dispositivi.
- **Problemi di sicurezza**: gravità, dispositivo, cosa significa e cosa fare. Si possono segnare come risolti, falso positivo o rischio accettato (con motivazione).
- **Avvisi** via e-mail e notifica push per i problemi gravi; **report PDF** scaricabile.
- **Assistente di sicurezza**: risponde a domande sui risultati della propria abitazione, usando solo i dati del proprio account; non esegue azioni.

## 6. App mobile

L'app (Android/iOS) mostra punteggio, problemi e avvisi, e riceve le notifiche push. L'accesso usa lo stesso account della dashboard.

## 7. Integrazioni

**Home Assistant**: con un token di lunga durata creato in Home Assistant, l'agent legge l'inventario dei dispositivi (anche Zigbee, Z-Wave, Matter, Bluetooth) in sola lettura, purché Home Assistant sia in una rete autorizzata. I dati compaiono nel dettaglio della scansione, ma non entrano nel punteggio. I dispositivi Matter si vedono solo tramite Home Assistant.

## 8. Abbonamento e white label

- Pagina *Abbonamento*: scelta del piano, pagamento su Stripe (i dati della carta non passano dal nostro server), gestione di fatture, carta e disdetta dal portale Stripe.
- Se attiva, la prova gratuita è offerta una sola volta: la carta viene addebitata solo alla fine della prova. Se il primo pagamento fallisce si torna al piano FREE senza perdere dati.
- Piano PRO: nome, colore e logo dell'organizzazione nella dashboard e nei report PDF.

## 9. Privacy e sicurezza

- I dati di ogni account/organizzazione sono separati dagli altri.
- I risultati delle scansioni restano sul server del servizio; ai feed pubblici di vulnerabilità non viene inviato nulla dell'utente.
- Per segnalare un problema di sicurezza usare l'indirizzo di supporto indicato nella dashboard.
