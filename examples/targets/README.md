# Bersagli vulnerabili per il demo di Gauntlet

Ambienti **deliberatamente vulnerabili**, pensati per essere attaccati, eseguiti
**in locale via Docker**. Non puntare Gauntlet contro sistemi che non possiedi o
per cui non hai autorizzazione esplicita.

## OWASP Juice Shop (falle web classiche)

```sh
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
# → http://localhost:3000  (dal container ZAP: http://host.docker.internal:3000)
```

Contratto: `examples/juiceshop/gauntlet.yaml`. Esecuzione (livello 1 — cieco):

```sh
python -m gauntlet run --project examples/juiceshop --level 1
```

## crAPI — completely ridiculous API (multi-tenant, BOLA/IDOR, JWT)

Stack multi-container: mostra il test di isolamento tra clienti. Il compose qui
in cartella (`docker-compose.crapi.yml`) è quello ufficiale OWASP con due
modifiche locali: rimosse le porte host 8888/8443 (in conflitto) — crAPI resta su
**30080** (http) / 30443 (https).

```sh
cd examples/targets
# 0.0.0.0 così anche il container ZAP raggiunge crAPI via host.docker.internal
LISTEN_IP=0.0.0.0 docker compose -f docker-compose.crapi.yml up -d
```

Setup dei due utenti di prova (contratto `examples/crapi/gauntlet.yaml`):

1. Registra due utenti via API:
   `POST http://localhost:30080/identity/api/auth/signup` con
   `{"name","email":"gauntlet-a@example.com","number","password":"Gauntlet!123"}`
   (e idem per `gauntlet-b@example.com`).
2. Assegna a ciascuno un veicolo con un UUID noto (crAPI semina veicoli senza
   proprietario; in un bersaglio usa-e-getta si assegnano via DB):
   `update vehicle_details set owner_id=<id_utente> where uuid='<uuid veicolo>';`
   L'oracolo di proprietà usa l'**email del proprietario** come `seed_marker`:
   l'endpoint vulnerabile `/identity/api/v2/vehicle/{uuid}/location` la restituisce
   nel corpo, quindi un accesso cross-tenant la fa trapelare.
3. Esegui (le password stanno in variabili d'ambiente, mai nel contratto):

```sh
CRAPI_A_PW='Gauntlet!123' CRAPI_B_PW='Gauntlet!123' \
  python -m gauntlet run --project examples/crapi --level 2
```

I report generati finiscono in `examples/results/` e sono riassunti in
`examples/README.md`.
