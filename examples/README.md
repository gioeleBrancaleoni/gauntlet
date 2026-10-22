# Risultati reali dell'applicazione di Gauntlet

Questa cartella raccoglie i report prodotti lanciando Gauntlet contro bersagli
**deliberatamente vulnerabili**, eseguiti in locale via Docker. Dimostrano cosa
la skill trova quando viene applicata a un'app reale. Istruzioni di avvio dei
bersagli: [`targets/README.md`](targets/README.md).

> Tutti i run sono su `localhost` (allowlist fail-closed), solo dev/stage.

## OWASP Juice Shop — livello 1 (cieco, non autenticato)

- Contratto: [`juiceshop/gauntlet.yaml`](juiceshop/gauntlet.yaml)
- Comando: `python -m gauntlet run --project examples/juiceshop --level 1`
- Report completo: [`results/juiceshop-level1-report.md`](results/juiceshop-level1-report.md)

**Esito:** 262 problemi rilevati — 0 critica, 0 alta, **170 media**, 92 info.
Tutto da scansione automatica ZAP sulla superficie pubblica, senza login.

Tipi principali:

| Conteggio | Finding | Gravità |
|---|---|---|
| 94 | Cross-Domain Misconfiguration (CORS `Access-Control-Allow-Origin: *`) | media |
| 76 | Content Security Policy (CSP) Header Not Set | media |
| 68 | Modern Web Application (informativo) | info |
| 24 | User Agent Fuzzer (informativo) | info |

I conteggi alti derivano dal fatto che lo stesso difetto (header mancante/permissivo)
si ripete su molte risorse della SPA: è il comportamento atteso di una scansione
a tappeto. Il livello 1 non autentica, quindi non esercita né l'auth a token né il
test di isolamento tra clienti — quelli si vedono su crAPI.

## crAPI — multi-tenant, BOLA/IDOR, JWT — livello 2 (autenticato)

- Contratto: [`crapi/gauntlet.yaml`](crapi/gauntlet.yaml)
- Comando: `CRAPI_A_PW=… CRAPI_B_PW=… python -m gauntlet run --project examples/crapi --level 2`
- Report completo: [`results/crapi-level2-report.md`](results/crapi-level2-report.md)

**Esito:** 12 problemi — **3 CRITICA**, 3 media, 5 bassa, 1 info.

Due CRITICA sono il pezzo forte: **leak cross-tenant BOLA/IDOR confermati dall'oracolo di proprietà**. `cliente_b`, con il proprio token, legge l'endpoint della location del veicolo di `cliente_a` e riceve `200` con `"email":"gauntlet-a@example.com"` nel corpo (e simmetricamente A legge i dati di B) — confidenza 100%. È il tipo di bug che l'analisi statica non vede e che solo un attacco reale, con due account e un marcatore noto, conferma senza falsi positivi.

La terza CRITICA è una debolezza JWT: **`alg=none` accettato** — il server honora un token forgiato senza firma (stessa payload, firma vuota) e restituisce la risorsa protetta. Significa che chiunque può fabbricare un token valido per qualsiasi utente. Trovata dal controllo debolezze JWT (confidenza 100%).

Il resto (header mancanti, version leak, CSP) viene dalla scansione passiva ZAP. Al livello 2 di default lo scan attivo intrusivo NON gira (serve `--aggressive`).

> Setup bersaglio: due utenti di prova registrati, ognuno con un veicolo assegnato e l'email come marcatore. Dettagli e avvio in [`targets/README.md`](targets/README.md).

---

## Verifica dal vivo dei nuovi moduli (2026-10-22)

Eseguiti con la skill completa contro bersagli reali in Docker:

- **CORS** — SCATTATO dal vivo su Juice Shop (`Access-Control-Allow-Origin: *`): finding del modulo `cors_checks` (confidenza 100%), distinto dagli alert passivi ZAP.
- **Rate-limiting login** — SCATTATO dal vivo su crAPI: "Nessun rate limiting sul login" (alta, conf 0.6) — 8 login falliti, nessun 429.
- **BOLA cross-tenant** e **JWT alg=none** — SCATTATI su crAPI (3 CRITICA), con gli oracoli induriti post-audit.
- **Missing-auth** ed **error-disclosure** — correttamente NON scattati su crAPI (endpoint autenticati, errori puliti): nessun falso positivo = comportamento atteso.
- **IDOR sequenziale** — verificato dai test (crAPI usa UUID, non ID numerici, quindi nessun caso positivo dal vivo).

**Limite di robustezza noto:** lo scan attivo ZAP in `--aggressive` può far cadere il container ZAP sotto pressione di memoria (stack crAPI ~4GB + active scan su macchina da 7,7GB); in tal caso il run attuale si interrompe. Miglioramento futuro: rendere non fatale il fallimento dell'active scan e scrivere comunque i findings httpx già raccolti.
