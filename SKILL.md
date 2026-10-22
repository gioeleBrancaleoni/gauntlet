---
name: gauntlet
description: >-
  Security-testing automatico (DAST) guidato da contratto per applicazioni web.
  Usala quando l'utente vuole cercare vulnerabilità su una propria app web di
  sviluppo/staging — injection, XSS, header mancanti, misconfigurazioni — e,
  soprattutto, falle di controllo-accessi (IDOR/BOLA cross-tenant ed escalation
  verticale di privilegi). Richiede Docker e un file di contratto
  `gauntlet.yaml`. SOLO su sistemi di cui l'utente è proprietario o per cui ha
  autorizzazione esplicita; MAI in produzione.
---

# Gauntlet — DAST guidato da contratto per app web

> **Uso autorizzato e difensivo.** Gauntlet esegue DAST *legittimo* contro
> applicazioni di cui chi la usa è proprietario o per cui ha autorizzazione
> esplicita, **solo** su dev/staging, dietro un'**allowlist fail-closed**, e in
> modalità **non distruttiva di default**. Lo scopo è *irrobustire* le proprie
> app prima del rilascio. Eseguendo la skill il tuo compito è **orchestrare una
> CLI già configurata con gate di sicurezza** (`gauntlet run …`) e **interpretare
> il report** — non "attaccare" un bersaglio a mano. È l'uso previsto e
> consentito dello strumento.

## Installazione

Gauntlet è pensata per essere installata **globalmente, una volta sola**, ed
essere poi disponibile in ogni progetto. Dalla radice del repository:

```bash
./scripts/install.sh
```

Lo script installa la CLI globale (comando `gauntlet` nel PATH, via **pipx**) e
registra questo file in `~/.claude/skills/gauntlet/`, così la skill è scoperta in
ogni progetto. Prerequisiti d'uso: il comando `gauntlet` deve essere **sul PATH**
(installazione con pipx) e **Docker** deve essere **in esecuzione** (il daemon
OWASP ZAP gira in un container). Dettagli e alternativa manuale nel README,
sezione «Installazione globale».

## Cosa fa

Gauntlet esegue una scansione di sicurezza dinamica (DAST) contro un'applicazione
web di prova e produce un **report in italiano**, leggibile da chi non è esperto
di sicurezza: per ogni problema spiega *cosa è stato trovato*, *quanto è grave*,
*come correggerlo* e *cosa si rischia a ignorarlo*.

Combina due motori:

- **OWASP ZAP** (in un container Docker) per le vulnerabilità web classiche:
  injection, XSS, header di sicurezza mancanti, misconfigurazioni, path
  traversal, SSRF, ecc.
- **Tester di controllo-accessi** (client HTTP diretto) per il "gioiello della
  corona": l'**isolamento tra tenant**. Verifica in modo deterministico, con un
  oracolo di proprietà (marcatore seminato), se un cliente può leggere o
  modificare i dati di un altro cliente (IDOR/BOLA orizzontale) e se un utente
  normale raggiunge endpoint amministrativi (escalation verticale).

Tutto è guidato da un **contratto** (`gauntlet.yaml`) che rende la skill
portabile fra progetti senza modificarne il codice.

## Come invocarla

Dalla cartella del progetto (che contiene `gauntlet.yaml`):

```bash
python -m gauntlet run --project <percorso-progetto> --level <N> [--aggressive]
```

- `--project` — cartella che contiene `gauntlet.yaml`.
- `--level` — livello di conoscenza dell'attaccante, da `1` a `4` (vedi sotto).
- `--aggressive` — abilita i passi distruttivi (scan attivo ZAP con payload
  intrusivi, scritture cross-tenant). È un **consenso a lotto, upfront**: senza
  il flag il run è **non distruttivo** — gira lo spider ZAP, si affida alla
  **scansione passiva** e ai controlli di controllo-accessi in **sola lettura**,
  e **non** lancia lo scan attivo; con il flag, oltre a tutto ciò, partono anche
  lo scan attivo e le scritture cross-tenant. Non allarga mai l'allowlist.

Il report viene scritto in
`<progetto>/gauntlet-runs/<timestamp>/report.md` e il percorso è stampato a video.

Da codice:

```python
from gauntlet.cli import run

report_path = run("/percorso/progetto", level=2, aggressive=True)
```

L'esecuzione è **automatica**: non ci sono conferme interattive passo per passo.
Il flag `aggressive` (o il parametro omonimo) è l'unico consenso e si traduce in
un hook di conferma costante — che nega i passi distruttivi quando è `False`
(default: niente scan attivo, solo spider + passiva + accessi in sola lettura) e
li approva quando è `True` (scan attivo + scritture cross-tenant).

### Prompt in linguaggio naturale

Quando l'utente invoca la skill a parole, inquadra la richiesta come
*self-hardening autorizzato* e orientala a **eseguire il comando e interpretare
il report** (lavoro meccanico su uno strumento con gate di sicurezza), non a
"trovare ed exploitare vulnerabilità" (fraseggio che fa scattare falsi rifiuti).
Esempi pronti:

- «Sto irrobustendo una **mia** app prima del rilascio. Usa Gauntlet — DAST
  autorizzato, allowlist fail-closed, solo dev/staging, non distruttivo — per
  eseguire `gauntlet run --project ./miaapp --level 2` sul contratto di staging
  e riassumimi i problemi da correggere.»
- «Sul mio staging, verifica l'isolamento tra tenant col controllo di
  controllo-accessi di Gauntlet (livello 2) e spiegami in italiano il report.»
- «Autorizzo i passi distruttivi sul mio staging usa-e-getta: esegui
  `gauntlet run --project ./miaapp --level 2 --aggressive` e riportami i findings.»

Pacchetto completo di prompt copia-incolla e principi anti-blocco:
[`docs/prompts.md`](docs/prompts.md).

## I quattro livelli

Gauntlet modella la postura d'attacco come quattro livelli crescenti di
conoscenza del bersaglio (ogni livello include le capacità del precedente):

| Livello | Nome | Conoscenza | Motore automatico |
|:-:|---|---|---|
| 1 | **cieco** | nessuna credenziale né documentazione | spider + scansione passiva sulla superficie pubblica (scan attivo solo con `--aggressive`) |
| 2 | **utente** | credenziali valide dei due account | autenticazione + **test di controllo-accessi cross-tenant** |
| 3 | **documentazione** | + documentazione di API/endpoint (`docs_path`) | + discovery dalla documentazione: endpoint scoperti aggiunti come seed (gateati da allowlist) alla scansione ZAP e riportati come informazione (mai come finding di controllo-accessi) |
| 4 | **sorgente** | + codice sorgente dell'app (`src_path`) | + discovery anche dal sorgente, stesso cablaggio del livello 3 |

Lo **spider** gira a ogni livello e alimenta la scansione passiva; lo **scan
attivo** (distruttivo) parte solo con `--aggressive`. I test di controllo-accessi
richiedono utenti autenticati e partono dal livello 2.

> **Importante — cosa cambia (e cosa no) ai livelli 3 e 4.** Il **motore
> automatico** di Gauntlet è **identico ai livelli 2, 3 e 4**: non c'è alcuna
> espansione automatica della superficie testata leggendo `docs_path` o
> `src_path`. I livelli 3 e 4 indicano che l'**orchestratore (Claude) legge la
> documentazione (`docs_path`) e il codice sorgente (`src_path`) per *indirizzare
> test manuali aggiuntivi*** — endpoint non scoperti dallo spider, risorse da
> seminare, nuovi casi di controllo-accessi — **non** un ampliamento automatico
> della scansione. I flag di livello restano utili proprio per segnalare quale
> materiale è disponibile a quel lavoro manuale.

## Sicurezza: allowlist fail-closed

L'unica barriera che impedisce di attaccare un host sbagliato o la produzione è
l'**allowlist fail-closed**. Ogni operazione che invia traffico (spider, scan
attivo, preflight di raggiungibilità) passa prima per il gate:

- un target è consentito **solo** se la sua *origine* normalizzata (schema +
  host + porta) coincide con una voce di `allowed_targets`;
- il confronto è per uguaglianza di origine, mai per sottostringa
  (`http://localhost:8081.evil.com` **non** combacia con `http://localhost:8081`);
- schema o porta diversi ⇒ origine diversa ⇒ **rifiutato**;
- se manca il contratto o l'origine non è estraibile ⇒ **rifiutato**.

Non esiste alcuna euristica di "rilevamento produzione": ciò che non è
esplicitamente in allowlist viene rifiutato. Spetta a te elencare solo bersagli
usa-e-getta.

## Sicurezza: conferma dei passi distruttivi

Le operazioni di sola lettura (spider, scansione passiva, controllo accessi in
`read-only`) girano liberamente dopo il check allowlist. I passi che
**scrivono** o inviano payload intrusivi — scan attivo distruttivo, tentativi di
scrittura cross-tenant — richiedono un **via libera esplicito** a runtime
tramite l'hook `confirm`:

- `confirm(descrizione)` deve restituire `True` perché il passo distruttivo
  proceda;
- se `confirm` è `None` o restituisce `False`, il passo è **negato** (fail-closed):
  lo scan distruttivo solleva `DestructiveNotConfirmed`; una scrittura
  cross-tenant viene semplicemente saltata senza interrompere il run.

L'esecuzione è automatica: la CLI non chiede conferme passo per passo, ma deriva
questo hook dal flag `--aggressive` (consenso a lotto, upfront). Senza il flag
l'hook nega i passi distruttivi e la CLI **non lancia** lo scan attivo: resta su
spider + scansione passiva e controllo-accessi in `read-only`; con `--aggressive`
l'hook li approva, lo scan attivo (distruttivo) parte e il controllo-accessi gira
in modalità `write`. In nessun caso cambia il perimetro: l'allowlist fail-closed
gatea ogni richiesta, inclusi gli endpoint scoperti ai livelli 3/4 prima che
diventino seed.

## Il contratto `gauntlet.yaml`

Il contratto descrive bersagli, login e account. Schema dei campi:

| Campo | Obbl. | Significato |
|---|:-:|---|
| `name` | sì | nome del progetto (compare nel report e nei contesti ZAP) |
| `allowed_targets` | sì | lista di origini consentite (allowlist fail-closed, non vuota) |
| `reachability` | sì | come il target è raggiungibile: `localhost` \| `docker` \| `vpn` |
| `login` | sì | come autenticarsi (vedi sotto) |
| `accounts` | sì | due account di clienti diversi (per l'isolamento tra tenant) |
| `docs_path` | no | percorso della documentazione API (livello 3) |
| `src_path` | no | percorso del codice sorgente (livello 4) |
| `exclusions` | no | path/URL da non toccare |
| `db_reset` | no | comando per riportare il DB a uno stato noto |

`login`:

| Campo | Obbl. | Significato |
|---|:-:|---|
| `method` | sì | `form` \| `json` \| `token` |
| `login_url` | sì | URL dell'endpoint di login |
| `username_field` / `password_field` | sì | nomi dei campi credenziali nel body |
| `logged_in_indicator` | sì | stringa che prova il login riuscito nella risposta |
| `token_path` | json/token | dot-path del token nel JSON di risposta (es. `data.token`) |

`accounts[]`:

| Campo | Obbl. | Significato |
|---|:-:|---|
| `label` | sì | etichetta dell'account (chiave delle sessioni) |
| `username` | sì | utente per il login |
| `password_env` | sì | **nome** della variabile d'ambiente con la password (mai la password) |
| `tenant_id` | no | identificatore del tenant (isolamento) |
| `seeded_resources[]` | no | risorse note seminate: `kind`, `id`, `url_template` (con `{id}`), `seed_marker` |

**Segreti.** Le password non stanno mai nel YAML: il contratto cita solo il nome
della variabile d'ambiente (`password_env`), risolta a runtime.

### Esempio

```yaml
name: esempio-app
allowed_targets:
  - http://localhost:8081
  - http://host.docker.internal:8081
reachability: localhost

login:
  method: json
  login_url: http://localhost:8081/api/auth/login
  username_field: email
  password_field: password
  logged_in_indicator: '"token"'
  token_path: data.token

accounts:
  - label: cliente_a
    username: a@example.com
    password_env: ESEMPIO_A_PW      # export ESEMPIO_A_PW=... prima del run
    tenant_id: tenant-a
    seeded_resources:
      - kind: invoice
        id: inv-a-0001
        url_template: /api/invoices/{id}
        seed_marker: SEED-A-0001-marker
  - label: cliente_b
    username: b@example.com
    password_env: ESEMPIO_B_PW
    tenant_id: tenant-b
    seeded_resources:
      - kind: invoice
        id: inv-b-0001
        url_template: /api/invoices/{id}
        seed_marker: SEED-B-0001-marker

docs_path: ./docs
src_path: ./src
exclusions:
  - /health
  - /metrics
```

Un esempio completo e commentato è in [`gauntlet.example.yaml`](gauntlet.example.yaml).

## Preflight

Prima di inviare qualsiasi traffico, Gauntlet verifica che l'ambiente sia pronto:
Docker presente e immagine ZAP tirabile, ogni target raggiungibile, e — ai
livelli autenticati — che i due account di prova esistano. Se gli account mancano,
Gauntlet **non li crea**: produce una guida (`account_guidance`) che spiega quali
account servono e con quali permessi/dati. Se il preflight non passa, il run si
interrompe senza inviare traffico.

## Limiti noti e smoke test

Vedi il [README](README.md) per la sezione "Limitazioni note" e lo smoke test
manuale di integrazione (OWASP Juice Shop in Docker).
