"""Localizzazione del report: scelta della lingua e catalogo dei messaggi.

Il report può essere prodotto in italiano (``it``) o in inglese (``en``). La
scelta è automatica:

* **auto (default):** si rileva la lingua di sistema; se è supportata si usa,
  altrimenti si ripiega sull'inglese.
* **override esplicito:** se viene richiesta una lingua precisa la si usa; un
  valore esplicito non supportato ripiega comunque sull'inglese.

Tutte le stringhe *nostre* (le impalcature del report e i finding generati da
Gauntlet) passano dal catalogo :data:`MESSAGES`. Il contenuto degli alert ZAP
**non** viene tradotto: resta come ZAP lo fornisce (inglese).

Funzioni pubbliche: :func:`resolve_language`, :func:`t`, :func:`severity_label`,
:func:`severity_hint`, :func:`source_label`.
"""

from __future__ import annotations

import locale
import os

#: Lingue supportate per il report. L'italiano è la lingua storica; l'inglese è
#: il ripiego quando la lingua di sistema non è supportata.
SUPPORTED: tuple[str, ...] = ("it", "en")

#: Variabili d'ambiente consultate, in ordine di precedenza, per rilevare la
#: lingua di sistema.
_ENV_VARS: tuple[str, ...] = ("LC_ALL", "LC_MESSAGES", "LANG")

#: Lingua di ripiego quando nulla di supportato è determinabile.
_FALLBACK = "en"


def _two_letter(value: str | None) -> str:
    """Prefisso di due lettere, minuscolo, di un valore di locale (o ``''``).

    Da ``it_IT.UTF-8`` ricava ``it``; da ``None``/vuoto ricava ``''``.
    """
    if not value:
        return ""
    return value[:2].lower()


def _detect_system_language() -> str:
    """Prefisso a due lettere della lingua di sistema, o ``''`` se ignota.

    Consulta nell'ordine ``LC_ALL``, ``LC_MESSAGES``, ``LANG``; in mancanza
    ripiega su :func:`locale.getlocale`. Non filtra per lingua supportata: è il
    chiamante (:func:`resolve_language`) a decidere il ripiego.
    """
    for var in _ENV_VARS:
        prefix = _two_letter(os.environ.get(var))
        if prefix:
            return prefix
    loc = locale.getlocale()[0]
    return _two_letter(loc)


def resolve_language(explicit: str | None = None) -> str:
    """Risolve la lingua del report. Non solleva mai.

    :param explicit: lingua richiesta. Se è ``None`` o ``"auto"`` si rileva la
        lingua di sistema e, se supportata, la si usa; altrimenti si ripiega
        sull'inglese. Se è una lingua supportata la si restituisce; un valore
        esplicito **non** supportato (es. ``"de"``) ripiega anch'esso
        sull'inglese.
    :returns: un codice lingua appartenente a :data:`SUPPORTED`.
    """
    if explicit is not None and explicit != "auto":
        return explicit if explicit in SUPPORTED else _FALLBACK
    try:
        detected = _detect_system_language()
    except Exception:
        # La rilevazione non deve mai interrompere un run: qualsiasi errore
        # (locale non configurato, ambiente anomalo) ripiega sull'inglese.
        return _FALLBACK
    return detected if detected in SUPPORTED else _FALLBACK


def t(lang: str, key: str, /, **fmt: object) -> str:
    """Restituisce la stringa localizzata ``key`` per ``lang``.

    Se la chiave manca nella lingua richiesta si ripiega sull'inglese e, in
    ultima istanza, sulla chiave stessa. Gli eventuali ``fmt`` sono applicati
    con :meth:`str.format`.
    """
    table = MESSAGES.get(lang) or MESSAGES[_FALLBACK]
    value = table.get(key)
    if value is None:
        value = MESSAGES[_FALLBACK].get(key, key)
    return value.format(**fmt) if fmt else value


def severity_label(lang: str, severity: str) -> str:
    """Etichetta leggibile della gravità (``CRITICA``/``CRITICAL`` …).

    Per una gravità sconosciuta ripiega sul valore in maiuscolo, senza mai
    sollevare: così il report non si rompe su un enum inatteso.
    """
    table = MESSAGES.get(lang) or MESSAGES[_FALLBACK]
    return table.get(f"sev_{severity}", severity.upper())


def severity_hint(lang: str, severity: str) -> str:
    """Spiegazione, in parole semplici, di quanto è urgente una gravità."""
    table = MESSAGES.get(lang) or MESSAGES[_FALLBACK]
    return table.get(f"sevhint_{severity}", "")


def source_label(lang: str, source: str) -> str:
    """Come si legge l'origine di un risultato, senza sigle da addetti ai lavori."""
    table = MESSAGES.get(lang) or MESSAGES[_FALLBACK]
    return table.get(f"src_{source}", source)


#: Catalogo dei messaggi. Una tabella per lingua; le due tabelle hanno le stesse
#: chiavi. Le stringhe italiane sono quelle storiche (immutate, così i test e i
#: report esistenti restano identici); quelle inglesi ne sono la traduzione
#: fedele.
MESSAGES: dict[str, dict[str, str]] = {
    "it": {
        # --- gravità (etichette e spiegazioni) ---
        "sev_critica": "CRITICA",
        "sev_alta": "ALTA",
        "sev_media": "MEDIA",
        "sev_bassa": "BASSA",
        "sev_info": "INFO",
        "sevhint_critica": "da correggere subito: può causare un danno grave e concreto.",
        "sevhint_alta": "importante: va corretto al più presto.",
        "sevhint_media": "da sistemare: non è un'emergenza, ma non va trascurato.",
        "sevhint_bassa": "miglioria consigliata: rischio limitato.",
        "sevhint_info": "solo informativo: nessuna azione urgente richiesta.",
        # --- origine del controllo ---
        "src_zap": "scansione automatica (ZAP)",
        "src_access-control": "test di controllo degli accessi",
        "src_jwt": "controllo delle debolezze JWT",
        "src_cors": "controllo della configurazione CORS",
        "src_rate-limit": "controllo del rate limiting sul login",
        "src_error-disclosure": "controllo della divulgazione di errori",
        "src_open-redirect": "controllo dell'open redirect",
        "src_mass-assignment": "controllo del mass assignment",
        # --- impalcatura del report (report.py) ---
        "report_title": "# Report di sicurezza — Gauntlet",
        "report_intro": (
            "Questo documento elenca i problemi di sicurezza rilevati sull'applicazione,\n"
            "spiegati in modo semplice. Per ciascuno trovi **cosa è stato trovato**, **quanto\n"
            "è grave**, **come correggerlo** e **cosa rischi se lo ignori**. I problemi sono\n"
            "ordinati dal più urgente al meno urgente."
        ),
        "meta_section": "## Dati dell'esecuzione",
        "meta_unspecified": "non specificato",
        "meta_target": "- **Bersaglio analizzato (target):** {target}",
        "meta_level": "- **Livello di conoscenza:** {livello}",
        "meta_aggressive": "- **Modalità aggressiva:** {modalita}",
        "meta_date": "- **Data e ora:** {data}",
        "meta_zap_interrupted": (
            "> ⚠️ **Scansione ZAP interrotta:** copertura passiva/attiva parziale "
            "({motivo})."
        ),
        "yes": "sì",
        "no": "no",
        "sensitive_warning": (
            "> ⚠️ **Attenzione — dati sensibili.** Le sezioni \"Prova concreta\" di "
            "questo report possono contenere estratti delle risposte (dati reali, "
            "PII, token di sessione) catturati dai controlli: trattalo come un "
            "documento riservato, non condividerlo né archiviarlo in chiaro senza "
            "averlo prima rivisto e oscurato."
        ),
        "endpoints_section": "## Endpoint scoperti (documentazione/sorgente)",
        "endpoints_intro": (
            "Questi endpoint candidati sono stati ricavati da documentazione e/o "
            "codice sorgente e usati per ampliare la superficie testata (solo "
            "quelli nell'allowlist sono stati effettivamente sondati):"
        ),
        "summary_section": "## Riepilogo",
        "summary_total": "Totale problemi rilevati: **{total}**.",
        "issues_section": "## Problemi rilevati (dal più urgente)",
        "no_findings": (
            "## Esito\n\n"
            "Nessun problema di sicurezza è stato rilevato in questa esecuzione. "
            "Non significa che l'applicazione sia perfetta, ma i controlli eseguiti "
            "non hanno trovato nulla da correggere."
        ),
        "fh_severity": "**Gravità:**",
        "fh_found": "**Che cosa è stato trovato:**",
        "fh_where": "**Dove:**",
        "fh_evidence": "**Prova concreta:**",
        "fh_fix": "**Come correggere:**",
        "fh_impact": "**Se ignori il problema:**",
        "fh_origin": (
            "_Origine del controllo: {origine} · confidenza del rilevamento: {conf}._"
        ),
        # --- finding del controllo-accessi (access_control.py) ---
        "ac_horizontal_title": "Accesso cross-tenant confermato (IDOR/BOLA)",
        "ac_horizontal_desc": (
            "Il tenant '{attacker_label}' ha letto la risorsa {url}, di "
            "proprietà del tenant '{owner_label}': risposta {status} "
            "contenente il marcatore del seed '{marker}'. L'isolamento tra "
            "clienti è violato."
        ),
        "ac_horizontal_evidence": (
            "GET {url} come '{attacker_label}' -> {status}; "
            "marcatore '{marker}' presente nel corpo (estratto: {extract})."
        ),
        "ac_horizontal_fix": (
            "Imporre l'autorizzazione per oggetto lato server: ogni accesso a una "
            "risorsa deve verificare che appartenga al tenant della sessione, non "
            "fidarsi dell'ID in ingresso."
        ),
        "ac_horizontal_impact": (
            "Un cliente può leggere (e potenzialmente modificare) i dati di un "
            "altro cliente: violazione di riservatezza e, se applicabile, del GDPR."
        ),
        "ac_write_confirmed_title": (
            "Scrittura cross-tenant confermata (IDOR/BOLA in scrittura)"
        ),
        "ac_write_confirmed_desc": (
            "Il tenant '{attacker_label}' ha modificato la risorsa {url}, di "
            "proprietà del tenant '{owner_label}': risposta {status} e la "
            "mutazione è stata verificata rileggendo la risorsa come proprietario "
            "(marcatore della sonda presente nel corpo). L'isolamento tra clienti "
            "è violato in scrittura."
        ),
        "ac_write_confirmed_evidence": (
            "PATCH {url} come '{attacker_label}' -> {status}; "
            "re-GET come '{owner_label}' mostra il marcatore '{probe}' nel corpo "
            "(mutazione confermata)."
        ),
        "ac_write_confirmed_fix": (
            "Verificare la proprietà della risorsa anche sulle operazioni di "
            "scrittura, non solo in lettura."
        ),
        "ac_write_confirmed_impact": (
            "Un cliente può alterare o distruggere i dati di un altro cliente."
        ),
        "ac_write_unconfirmed_title": (
            "Possibile scrittura cross-tenant NON CONFERMATA (IDOR/BOLA in scrittura)"
        ),
        "ac_write_unconfirmed_desc": (
            "Il tenant '{attacker_label}' ha ottenuto una risposta {status} a una "
            "PATCH sulla risorsa {url}, di proprietà del tenant '{owner_label}'. "
            "La mutazione NON è stata confermata sulla risorsa della vittima "
            "(re-GET come proprietario non disponibile o marcatore della sonda "
            "assente): potrebbe trattarsi di un endpoint che risponde 2xx senza "
            "scrivere. Va verificata a mano."
        ),
        "ac_write_unconfirmed_evidence": (
            "PATCH {url} come '{attacker_label}' -> {status}; "
            "mutazione NON confermata da una re-GET come proprietario."
        ),
        "ac_write_unconfirmed_fix": (
            "Verificare la proprietà della risorsa anche sulle operazioni di "
            "scrittura, non solo in lettura; confermare a mano se la PATCH ha "
            "effettivamente modificato i dati della vittima."
        ),
        "ac_write_unconfirmed_impact": (
            "Se la scrittura va davvero a buon fine, un cliente può alterare o "
            "distruggere i dati di un altro cliente; da confermare manualmente."
        ),
        "ac_vertical_title": "Endpoint amministrativo raggiungibile da utente normale",
        "ac_vertical_desc": (
            "L'utente normale '{actor_label}' ha raggiunto l'endpoint "
            "amministrativo {url}: risposta {status}. Possibile escalation "
            "verticale di privilegi."
        ),
        "ac_vertical_evidence": (
            "GET {url} come '{actor_label}' -> {status} (estratto: {extract})."
        ),
        "ac_vertical_fix": (
            "Proteggere gli endpoint amministrativi con un controllo di ruolo "
            "lato server; non affidarsi a URL non pubblicizzati."
        ),
        "ac_vertical_impact": (
            "Un utente senza privilegi può accedere a funzioni o dati "
            "amministrativi dell'intera istanza."
        ),
        "ac_marker_title": "Risorsa priva di marcatore di seed distintivo",
        "ac_marker_desc": (
            "La risorsa {url} del tenant '{owner_label}' non ha un "
            "'seed_marker' dichiarato e il suo 'id' ('{resource_id}') non è un "
            "token abbastanza distintivo da usare come oracolo: il test "
            "cross-tenant su questa risorsa non è deterministico ed è stato "
            "saltato (nessun leak confermato)."
        ),
        "ac_marker_evidence": (
            "Risorsa {kind} id={resource_id_repr} senza seed_marker; "
            "oracolo di proprietà non disponibile."
        ),
        "ac_marker_fix": (
            "Dichiarare nel contratto un 'seed_marker' univoco e distintivo per "
            "questa risorsa (una stringa seminata nei dati del tenant), così il "
            "leak cross-tenant può essere confermato senza falsi positivi."
        ),
        "ac_marker_impact": (
            "Un eventuale leak su questa risorsa resterebbe non rilevato: va "
            "configurato un marcatore per poterla testare."
        ),
        # --- finding di autenticazione mancante/rotta (access_control.py) ---
        "ac_noauth_title": "Risorsa accessibile senza autenticazione",
        "ac_noauth_desc": (
            "La risorsa protetta {url}, di proprietà del tenant '{owner_label}', "
            "è stata servita a una richiesta ANONIMA (nessun token, nessun "
            "cookie): risposta {status} contenente il marcatore del seed "
            "'{marker}'. Il controllo di autenticazione è assente o aggirabile."
        ),
        "ac_noauth_evidence": (
            "GET {url} senza header Authorization e senza cookie -> {status}; "
            "marcatore '{marker}' presente nel corpo (estratto: {extract})."
        ),
        "ac_noauth_fix": (
            "Imporre l'autenticazione lato server su questa risorsa: una "
            "richiesta priva di sessione valida deve ricevere 401/403, mai il "
            "contenuto protetto."
        ),
        "ac_noauth_impact": (
            "Chiunque, senza alcuna credenziale, può leggere i dati protetti: "
            "esposizione pubblica di informazioni riservate e, se applicabile, "
            "violazione del GDPR."
        ),
        # --- finding IDOR su ID sequenziali (access_control.py, E2) ---
        "ac_seqidor_title": "IDOR su ID sequenziale confermato",
        "ac_seqidor_desc": (
            "Il tenant '{owner_label}' ({username}), sondando ID vicini a una "
            "risorsa propria, ha letto la risorsa {url}: risposta {status} con "
            "campo di proprietà '{owner_field}' = '{leaked_owner}', cioè di un "
            "ALTRO proprietario. Gli oggetti sono numerati e l'autorizzazione "
            "per oggetto non è imposta: indovinando l'ID si leggono dati altrui."
        ),
        "ac_seqidor_evidence": (
            "GET {url} come '{owner_label}' ({username}) -> {status}; "
            "campo '{owner_field}' nel corpo = '{leaked_owner}' "
            "(proprietario diverso da chi sonda; estratto: {extract})."
        ),
        "ac_seqidor_fix": (
            "Imporre l'autorizzazione per oggetto lato server su ogni accesso: "
            "verificare che la risorsa appartenga al tenant della sessione invece "
            "di fidarsi dell'ID in ingresso; valutare ID non indovinabili (UUID)."
        ),
        "ac_seqidor_impact": (
            "Un cliente può enumerare gli ID e leggere (o modificare) i dati di "
            "altri clienti: violazione di riservatezza e, se applicabile, del GDPR."
        ),
        # --- finding delle debolezze JWT (jwt_checks.py) ---
        "jwt_alg_none_title": "JWT alg=none accettato",
        "jwt_alg_none_desc": (
            "Il server ha accettato un token JWT forgiato con header "
            "'alg: none' e firma vuota (stessa payload del token reale): la "
            "GET su {url} ha risposto {status} con il contenuto protetto atteso. "
            "La firma del token non viene verificata: chiunque può fabbricare un "
            "token valido con qualsiasi identità e privilegio."
        ),
        "jwt_alg_none_evidence": (
            "GET {url} con un token 'alg: {alg}' a firma vuota -> {status}; "
            "il marcatore della risorsa protetta '{marker}' è presente nel corpo "
            "(token non firmato accettato)."
        ),
        "jwt_alg_none_fix": (
            "Rifiutare esplicitamente i token con 'alg: none' lato server e "
            "fissare l'algoritmo atteso (allowlist di algoritmi); non dedurre mai "
            "l'algoritmo di verifica dall'header del token."
        ),
        "jwt_alg_none_impact": (
            "Un attaccante può forgiare un token per qualsiasi utente "
            "(compreso un amministratore) e autenticarsi come chiunque: "
            "compromissione totale dell'autenticazione."
        ),
        "jwt_weak_secret_title": "Secret JWT debole: '{secret}'",
        "jwt_weak_secret_desc": (
            "La firma {alg} del token reale è stata riprodotta usando il segreto "
            "comune '{secret}': la chiave di firma è indovinabile. Chi conosce "
            "il segreto può fabbricare token validi con qualsiasi identità."
        ),
        "jwt_weak_secret_evidence": (
            "HMAC-{alg} su 'header.payload' con il segreto '{secret}' riproduce "
            "esattamente la firma del token (segreto confermato dalla wordlist)."
        ),
        "jwt_weak_secret_fix": (
            "Usare un segreto di firma lungo e casuale (almeno 256 bit), "
            "custodito fuori dal codice e ruotabile; mai un valore di default o "
            "da dizionario."
        ),
        "jwt_weak_secret_impact": (
            "Un attaccante può firmare token arbitrari e impersonare qualunque "
            "utente, inclusi gli amministratori: compromissione totale "
            "dell'autenticazione."
        ),
        "jwt_unverified_title": (
            "Endpoint non verifica la firma del token / accesso non autenticato"
        ),
        "jwt_unverified_desc": (
            "Un controllo negativo con un token dalla firma deliberatamente "
            "corrotta (stesso 'alg: {alg}' del token reale) è stato comunque "
            "accettato: la GET su {url} ha risposto {status} con il contenuto "
            "protetto atteso. L'endpoint non verifica la firma del token (o è di "
            "fatto non autenticato). Il meccanismo preciso è ambiguo: potrebbe "
            "essere alg=none, ma anche un endpoint pubblico o che ignora del tutto "
            "il token — per questo non si asserisce in modo specifico 'alg=none'."
        ),
        "jwt_unverified_evidence": (
            "GET {url} con un token 'alg: {alg}' a firma CORROTTA (controllo "
            "negativo) -> {status}; il marcatore '{marker}' è presente nel corpo. "
            "Un server che verifica la firma avrebbe rifiutato questo token."
        ),
        "jwt_unverified_fix": (
            "Verificare sempre la firma del token lato server con l'algoritmo "
            "atteso fissato (allowlist di algoritmi) e proteggere l'endpoint con "
            "autenticazione; rifiutare i token a firma non valida."
        ),
        "jwt_unverified_impact": (
            "Se la firma non è verificata, un attaccante può alterare i claim del "
            "token (identità, privilegi) senza conoscere il segreto; se l'endpoint "
            "è non autenticato, i dati protetti sono esposti a chiunque."
        ),
        # --- finding di configurazione CORS (cors_checks.py) ---
        "cors_credentialed_title": (
            "CORS: origine riflessa con credenziali abilitate"
        ),
        "cors_credentialed_desc": (
            "L'endpoint {url} ha riflesso nell'header "
            "'Access-Control-Allow-Origin' l'origine estranea della sonda "
            "('{probe}') e ha dichiarato 'Access-Control-Allow-Credentials: "
            "true'. Qualsiasi sito può quindi leggere, con i cookie di sessione "
            "della vittima, le risposte autenticate di questo endpoint."
        ),
        "cors_credentialed_evidence": (
            "GET {url} con 'Origin: {probe}' -> "
            "Access-Control-Allow-Origin: {acao}; "
            "Access-Control-Allow-Credentials: {acac}."
        ),
        "cors_credentialed_fix": (
            "Non riflettere mai l'header Origin: confrontarlo con un'allowlist di "
            "origini fidate e, solo per quelle, restituire l'origine esatta; non "
            "abbinare mai 'Allow-Credentials: true' a un'origine riflessa."
        ),
        "cors_credentialed_impact": (
            "Un sito malevolo può effettuare richieste autenticate come la "
            "vittima e leggerne le risposte: furto di dati e di sessione "
            "cross-origin."
        ),
        "cors_reflect_title": "CORS: origine estranea riflessa",
        "cors_reflect_desc": (
            "L'endpoint {url} ha riflesso nell'header "
            "'Access-Control-Allow-Origin' l'origine estranea della sonda "
            "('{probe}'), senza abilitare le credenziali. Qualsiasi sito può "
            "leggere le risposte (non autenticate) di questo endpoint."
        ),
        "cors_reflect_evidence": (
            "GET {url} con 'Origin: {probe}' -> "
            "Access-Control-Allow-Origin: {acao} "
            "(credenziali non abilitate)."
        ),
        "cors_reflect_fix": (
            "Non riflettere l'header Origin: consentire solo un'allowlist di "
            "origini fidate e restituire l'origine esatta solo per quelle."
        ),
        "cors_reflect_impact": (
            "Un sito di terze parti può leggere via browser le risposte di "
            "questo endpoint; grave se l'endpoint espone dati non pubblici anche "
            "senza credenziali."
        ),
        "cors_wildcard_title": "CORS: allow-origin con wildcard permissivo",
        "cors_wildcard_desc": (
            "L'endpoint {url} ha restituito 'Access-Control-Allow-Origin: *', "
            "consentendo a qualsiasi origine di leggerne le risposte via "
            "browser. Con il wildcard i browser ignorano "
            "'Allow-Credentials: true', quindi le richieste con credenziali non "
            "sono esposte, ma i dati non autenticati sì."
        ),
        "cors_wildcard_evidence": (
            "GET {url} con 'Origin: {probe}' -> "
            "Access-Control-Allow-Origin: * (wildcard)."
        ),
        "cors_wildcard_fix": (
            "Restringere 'Access-Control-Allow-Origin' a un'allowlist di origini "
            "fidate invece del wildcard, soprattutto su endpoint che espongono "
            "dati non pubblici."
        ),
        "cors_wildcard_impact": (
            "Qualsiasi sito può leggere via browser le risposte non autenticate "
            "di questo endpoint."
        ),
        # --- finding di open redirect (open_redirect_checks.py) ---
        "open_redirect_title": "Open redirect: destinazione non validata",
        "open_redirect_desc": (
            "L'endpoint {url} ha costruito un redirect verso la destinazione "
            "estranea della sonda ('{probe}') a partire da un parametro "
            "controllato dall'utente, senza validarla: la risposta contiene un "
            "header 'Location: {location}' che porta fuori dall'applicazione. Un "
            "attaccante può far redirigere la vittima su un sito arbitrario."
        ),
        "open_redirect_evidence": (
            "GET {url} (payload = '{probe}') -> risposta di redirect con "
            "'Location: {location}' verso l'host estraneo della sonda."
        ),
        "open_redirect_fix": (
            "Non costruire il redirect da un valore in ingresso non validato: "
            "consentire solo destinazioni relative alla propria applicazione o "
            "un'allowlist di URL/host fidati; rifiutare le destinazioni assolute "
            "o protocol-relative verso origini esterne."
        ),
        "open_redirect_impact": (
            "Un attaccante può usare un link del dominio fidato per spedire la "
            "vittima su un sito di phishing credibile o per sottrarre token in "
            "flussi OAuth/SSO; aggira inoltre i filtri basati sul dominio."
        ),
        # --- finding di assegnazione di massa (mass_assignment_checks.py) ---
        "mass_assignment_title": "Assegnazione di massa: campo protetto scrivibile dal client",
        "mass_assignment_desc": (
            "L'endpoint di update {url} ha accettato un campo protetto che il "
            "client non dovrebbe poter impostare: inviando {field} = "
            "{value} e poi rileggendo la risorsa, il campo risultava "
            "effettivamente modificato. L'applicazione fonde l'intero corpo "
            "della richiesta senza filtrare i campi assegnabili."
        ),
        "mass_assignment_evidence": (
            "Update su {url} con corpo {{\"{field}\": {value}}} -> la re-GET "
            "della risorsa mostra {field} = {value} (valore iniettato "
            "riflesso: scrittura confermata, non solo uno status 2xx)."
        ),
        "mass_assignment_fix": (
            "Filtrare lato server i campi assegnabili tramite update: usare "
            "un'allowlist esplicita dei campi modificabili dal client (binding "
            "selettivo) e rifiutare o ignorare ogni altro attributo, "
            "specialmente quelli di ruolo, proprietà o stato interno."
        ),
        "mass_assignment_impact": (
            "Un utente può elevare i propri privilegi o manomettere lo stato "
            "dell'oggetto (p.es. diventare amministratore o cambiare "
            "proprietario) impostando campi che dovrebbero essere di sola "
            "lettura."
        ),
        # --- finding di assenza di rate limiting sul login (ratelimit_checks.py) ---
        "rl_title": "Nessun rate limiting sul login",
        "rl_desc": (
            "In {attempts} tentativi di login falliti consecutivi verso {url} non "
            "è stato osservato alcun segnale di limitazione (nessuna risposta 429 "
            "né header 'Retry-After'). NB: è un'osservazione su {attempts} "
            "tentativi, non una prova assoluta — un limiter con soglia più alta o "
            "basato su IP potrebbe non essersi attivato in così pochi tentativi."
        ),
        "rl_evidence": (
            "{attempts} POST di login con password errata verso {url}: nessuna "
            "risposta 429 e nessun header Retry-After osservati."
        ),
        "rl_fix": (
            "Applicare rate limiting / backoff progressivo sui tentativi di login "
            "(per account e per IP), con blocco temporaneo dopo ripetuti "
            "fallimenti e, dove opportuno, CAPTCHA."
        ),
        "rl_impact": (
            "Senza limiti, un attaccante può tentare brute force o credential "
            "stuffing sulle credenziali degli utenti senza ostacoli."
        ),
        # --- finding di divulgazione errori/stack trace (error_disclosure_checks.py) ---
        "ed_title": "Divulgazione di errori/stack trace",
        "ed_desc": (
            "La richiesta a {url} con un id malformato ha restituito una risposta "
            "(stato {status}) contenente una firma tipica di stack trace o errore "
            "di framework/ORM: l'applicazione espone dettagli interni invece di un "
            "errore generico. Rilevamento basato su pattern (da confermare)."
        ),
        "ed_evidence": (
            "GET {url} -> {status}; firma rilevata: {signature} "
            "(estratto: {snippet})."
        ),
        "ed_fix": (
            "Restituire messaggi di errore generici al client e registrare i "
            "dettagli solo lato server; disabilitare debug/stack trace in "
            "produzione."
        ),
        "ed_impact": (
            "Un attaccante ricava tecnologia, versioni, percorsi del filesystem e "
            "struttura interna, utili a costruire attacchi mirati; talvolta "
            "trapelano frammenti di query o dati."
        ),
        # --- finding informativo della discovery (cli.py) ---
        "cli_discovery_title": (
            "Superficie aggiuntiva scoperta da documentazione/sorgente"
        ),
        "cli_discovery_desc": (
            "Sono stati scoperti {count} endpoint da documentazione "
            "e/o codice sorgente e aggiunti come seed alla scansione automatica "
            "(solo quelli già consentiti dall'allowlist). Ampliano la superficie "
            "analizzata da ZAP; non costituiscono di per sé un problema."
        ),
        "cli_discovery_evidence": "Endpoint aggiunti come seed di scansione:\n{righe}",
        "cli_discovery_fix": (
            "Nessuna azione richiesta: è un'informazione sulla copertura del "
            "test. Verifica che gli endpoint elencati siano quelli attesi."
        ),
        "cli_discovery_impact": (
            "Nessun impatto diretto: voce informativa sulla superficie testata."
        ),
        # --- output per l'operatore (cli.py) ---
        "cli_report_written": "Report scritto in: {path}",
        "cli_error": "Errore: {exc}",
        "cli_preflight_failed": (
            "Preflight non superato: l'ambiente non è pronto per il run."
        ),
    },
    "en": {
        # --- severity (labels and hints) ---
        "sev_critica": "CRITICAL",
        "sev_alta": "HIGH",
        "sev_media": "MEDIUM",
        "sev_bassa": "LOW",
        "sev_info": "INFO",
        "sevhint_critica": "fix immediately: it can cause serious, concrete harm.",
        "sevhint_alta": "important: fix it as soon as possible.",
        "sevhint_media": "worth fixing: not an emergency, but it should not be neglected.",
        "sevhint_bassa": "recommended improvement: limited risk.",
        "sevhint_info": "informational only: no urgent action required.",
        # --- finding source ---
        "src_zap": "automated scan (ZAP)",
        "src_access-control": "access-control test",
        "src_jwt": "JWT weakness check",
        "src_cors": "CORS configuration check",
        "src_rate-limit": "login rate-limiting check",
        "src_error-disclosure": "error/stack-trace disclosure check",
        "src_open-redirect": "open-redirect check",
        "src_mass-assignment": "mass-assignment check",
        # --- report scaffolding (report.py) ---
        "report_title": "# Security Report — Gauntlet",
        "report_intro": (
            "This document lists the security issues found in the application,\n"
            "explained in plain language. For each one you'll find **what was found**, **how\n"
            "serious it is**, **how to fix it** and **what you risk if you ignore it**. The issues\n"
            "are ordered from the most urgent to the least urgent."
        ),
        "meta_section": "## Run details",
        "meta_unspecified": "not specified",
        "meta_target": "- **Analyzed target:** {target}",
        "meta_level": "- **Knowledge level:** {livello}",
        "meta_aggressive": "- **Aggressive mode:** {modalita}",
        "meta_date": "- **Date and time:** {data}",
        "meta_zap_interrupted": (
            "> ⚠️ **ZAP scan interrupted:** partial passive/active coverage "
            "({motivo})."
        ),
        "yes": "yes",
        "no": "no",
        "sensitive_warning": (
            "> ⚠️ **Warning — sensitive data.** The \"Concrete evidence\" sections "
            "of this report may contain extracts of the responses (real data, "
            "PII, session tokens) captured by the checks: treat it as a "
            "confidential document, do not share it or store it in clear text "
            "without first reviewing and redacting it."
        ),
        "endpoints_section": "## Discovered endpoints (documentation/source)",
        "endpoints_intro": (
            "These candidate endpoints were derived from documentation and/or "
            "source code and used to widen the tested surface (only those in the "
            "allowlist were actually probed):"
        ),
        "summary_section": "## Summary",
        "summary_total": "Total issues found: **{total}**.",
        "issues_section": "## Issues found (most urgent first)",
        "no_findings": (
            "## Result\n\n"
            "No security issues were found in this run. This does not mean the "
            "application is perfect, but the checks that were run did not find "
            "anything to fix."
        ),
        "fh_severity": "**Severity:**",
        "fh_found": "**What was found:**",
        "fh_where": "**Where:**",
        "fh_evidence": "**Concrete evidence:**",
        "fh_fix": "**How to fix:**",
        "fh_impact": "**If you ignore the issue:**",
        "fh_origin": (
            "_Check source: {origine} · detection confidence: {conf}._"
        ),
        # --- access-control findings (access_control.py) ---
        "ac_horizontal_title": "Confirmed cross-tenant access (IDOR/BOLA)",
        "ac_horizontal_desc": (
            "Tenant '{attacker_label}' read resource {url}, owned by tenant "
            "'{owner_label}': response {status} containing the seed marker "
            "'{marker}'. Isolation between customers is broken."
        ),
        "ac_horizontal_evidence": (
            "GET {url} as '{attacker_label}' -> {status}; "
            "marker '{marker}' present in the body (extract: {extract})."
        ),
        "ac_horizontal_fix": (
            "Enforce per-object authorization on the server side: every access to "
            "a resource must verify that it belongs to the session's tenant, and "
            "not trust the incoming ID."
        ),
        "ac_horizontal_impact": (
            "A customer can read (and potentially modify) another customer's data: "
            "a confidentiality breach and, where applicable, a GDPR violation."
        ),
        "ac_write_confirmed_title": (
            "Confirmed cross-tenant write (write-side IDOR/BOLA)"
        ),
        "ac_write_confirmed_desc": (
            "Tenant '{attacker_label}' modified resource {url}, owned by tenant "
            "'{owner_label}': response {status} and the mutation was verified by "
            "re-reading the resource as the owner (probe marker present in the "
            "body). Isolation between customers is broken for writes."
        ),
        "ac_write_confirmed_evidence": (
            "PATCH {url} as '{attacker_label}' -> {status}; "
            "re-GET as '{owner_label}' shows the marker '{probe}' in the body "
            "(mutation confirmed)."
        ),
        "ac_write_confirmed_fix": (
            "Verify resource ownership on write operations too, not only on reads."
        ),
        "ac_write_confirmed_impact": (
            "A customer can alter or destroy another customer's data."
        ),
        "ac_write_unconfirmed_title": (
            "Possible UNCONFIRMED cross-tenant write (write-side IDOR/BOLA)"
        ),
        "ac_write_unconfirmed_desc": (
            "Tenant '{attacker_label}' got a {status} response to a PATCH on "
            "resource {url}, owned by tenant '{owner_label}'. The mutation was NOT "
            "confirmed on the victim's resource (re-GET as the owner unavailable "
            "or probe marker absent): it may be an endpoint that returns 2xx "
            "without writing. It must be checked manually."
        ),
        "ac_write_unconfirmed_evidence": (
            "PATCH {url} as '{attacker_label}' -> {status}; "
            "mutation NOT confirmed by a re-GET as the owner."
        ),
        "ac_write_unconfirmed_fix": (
            "Verify resource ownership on write operations too, not only on reads; "
            "manually confirm whether the PATCH actually modified the victim's data."
        ),
        "ac_write_unconfirmed_impact": (
            "If the write really succeeds, a customer can alter or destroy another "
            "customer's data; to be confirmed manually."
        ),
        "ac_vertical_title": "Administrative endpoint reachable by a normal user",
        "ac_vertical_desc": (
            "Normal user '{actor_label}' reached the administrative endpoint "
            "{url}: response {status}. Possible vertical privilege escalation."
        ),
        "ac_vertical_evidence": (
            "GET {url} as '{actor_label}' -> {status} (extract: {extract})."
        ),
        "ac_vertical_fix": (
            "Protect administrative endpoints with a server-side role check; "
            "do not rely on unadvertised URLs."
        ),
        "ac_vertical_impact": (
            "A user without privileges can access administrative functions or "
            "data of the entire instance."
        ),
        "ac_marker_title": "Resource without a distinctive seed marker",
        "ac_marker_desc": (
            "Resource {url} of tenant '{owner_label}' has no declared "
            "'seed_marker' and its 'id' ('{resource_id}') is not a token "
            "distinctive enough to use as an oracle: the cross-tenant test on this "
            "resource is not deterministic and was skipped (no confirmed leak)."
        ),
        "ac_marker_evidence": (
            "Resource {kind} id={resource_id_repr} without seed_marker; "
            "ownership oracle unavailable."
        ),
        "ac_marker_fix": (
            "Declare a unique, distinctive 'seed_marker' in the contract for this "
            "resource (a string seeded in the tenant's data), so the cross-tenant "
            "leak can be confirmed without false positives."
        ),
        "ac_marker_impact": (
            "A possible leak on this resource would go undetected: a marker must "
            "be configured to be able to test it."
        ),
        # --- missing/broken authentication finding (access_control.py) ---
        "ac_noauth_title": "Resource accessible without authentication",
        "ac_noauth_desc": (
            "The protected resource {url}, owned by tenant '{owner_label}', was "
            "served to an ANONYMOUS request (no token, no cookie): response "
            "{status} containing the seed marker '{marker}'. The authentication "
            "check is missing or bypassable."
        ),
        "ac_noauth_evidence": (
            "GET {url} with no Authorization header and no cookies -> {status}; "
            "marker '{marker}' present in the body (extract: {extract})."
        ),
        "ac_noauth_fix": (
            "Enforce authentication on the server side for this resource: a "
            "request without a valid session must receive 401/403, never the "
            "protected content."
        ),
        "ac_noauth_impact": (
            "Anyone, with no credentials at all, can read the protected data: a "
            "public exposure of confidential information and, where applicable, a "
            "GDPR violation."
        ),
        # --- sequential-ID IDOR finding (access_control.py, E2) ---
        "ac_seqidor_title": "Confirmed sequential-ID IDOR",
        "ac_seqidor_desc": (
            "Tenant '{owner_label}' ({username}), probing IDs neighboring one of "
            "its own resources, read resource {url}: response {status} with "
            "ownership field '{owner_field}' = '{leaked_owner}', i.e. a DIFFERENT "
            "owner. Objects are sequentially numbered and per-object authorization "
            "is not enforced: guessing an ID reveals another customer's data."
        ),
        "ac_seqidor_evidence": (
            "GET {url} as '{owner_label}' ({username}) -> {status}; "
            "field '{owner_field}' in the body = '{leaked_owner}' "
            "(owner differs from the probing account; extract: {extract})."
        ),
        "ac_seqidor_fix": (
            "Enforce per-object authorization on the server side for every access: "
            "verify the resource belongs to the session's tenant instead of "
            "trusting the incoming ID; consider unguessable IDs (UUIDs)."
        ),
        "ac_seqidor_impact": (
            "A customer can enumerate IDs and read (or modify) other customers' "
            "data: a confidentiality breach and, where applicable, a GDPR violation."
        ),
        # --- JWT weakness findings (jwt_checks.py) ---
        "jwt_alg_none_title": "JWT alg=none accepted",
        "jwt_alg_none_desc": (
            "The server accepted a JWT forged with an 'alg: none' header and an "
            "empty signature (same payload as the real token): the GET on {url} "
            "responded {status} with the expected protected content. The token "
            "signature is not verified: anyone can craft a valid token with any "
            "identity and privilege."
        ),
        "jwt_alg_none_evidence": (
            "GET {url} with an 'alg: {alg}' empty-signature token -> {status}; "
            "the protected resource marker '{marker}' is present in the body "
            "(unsigned token accepted)."
        ),
        "jwt_alg_none_fix": (
            "Explicitly reject 'alg: none' tokens on the server side and pin the "
            "expected algorithm (an algorithm allowlist); never infer the "
            "verification algorithm from the token header."
        ),
        "jwt_alg_none_impact": (
            "An attacker can forge a token for any user (including an "
            "administrator) and authenticate as anyone: a complete compromise of "
            "authentication."
        ),
        "jwt_weak_secret_title": "Weak JWT secret: '{secret}'",
        "jwt_weak_secret_desc": (
            "The real token's {alg} signature was reproduced using the common "
            "secret '{secret}': the signing key is guessable. Anyone who knows "
            "the secret can craft valid tokens with any identity."
        ),
        "jwt_weak_secret_evidence": (
            "HMAC-{alg} over 'header.payload' with the secret '{secret}' exactly "
            "reproduces the token signature (secret confirmed from the wordlist)."
        ),
        "jwt_weak_secret_fix": (
            "Use a long, random signing secret (at least 256 bits), kept out of "
            "the code and rotatable; never a default or dictionary value."
        ),
        "jwt_weak_secret_impact": (
            "An attacker can sign arbitrary tokens and impersonate any user, "
            "administrators included: a complete compromise of authentication."
        ),
        "jwt_unverified_title": (
            "Endpoint does not verify the token signature / unauthenticated access"
        ),
        "jwt_unverified_desc": (
            "A negative control with a deliberately corrupted signature (same "
            "'alg: {alg}' as the real token) was still accepted: the GET on {url} "
            "responded {status} with the expected protected content. The endpoint "
            "does not verify the token signature (or is effectively "
            "unauthenticated). The precise mechanism is ambiguous: it could be "
            "alg=none, but also a public endpoint or one that ignores the token "
            "entirely — so 'alg=none' is not asserted specifically."
        ),
        "jwt_unverified_evidence": (
            "GET {url} with an 'alg: {alg}' CORRUPTED-signature token (negative "
            "control) -> {status}; the marker '{marker}' is present in the body. "
            "A server that verifies the signature would have rejected this token."
        ),
        "jwt_unverified_fix": (
            "Always verify the token signature server-side with the expected "
            "algorithm pinned (an algorithm allowlist) and protect the endpoint "
            "with authentication; reject tokens with an invalid signature."
        ),
        "jwt_unverified_impact": (
            "If the signature is not verified, an attacker can alter the token's "
            "claims (identity, privileges) without knowing the secret; if the "
            "endpoint is unauthenticated, the protected data is exposed to anyone."
        ),
        # --- CORS configuration findings (cors_checks.py) ---
        "cors_credentialed_title": (
            "CORS: origin reflected with credentials enabled"
        ),
        "cors_credentialed_desc": (
            "Endpoint {url} reflected the probe's foreign origin ('{probe}') in "
            "the 'Access-Control-Allow-Origin' header and declared "
            "'Access-Control-Allow-Credentials: true'. Any website can therefore "
            "read this endpoint's authenticated responses using the victim's "
            "session cookies."
        ),
        "cors_credentialed_evidence": (
            "GET {url} with 'Origin: {probe}' -> "
            "Access-Control-Allow-Origin: {acao}; "
            "Access-Control-Allow-Credentials: {acac}."
        ),
        "cors_credentialed_fix": (
            "Never reflect the Origin header: compare it against an allowlist of "
            "trusted origins and return the exact origin only for those; never "
            "pair 'Allow-Credentials: true' with a reflected origin."
        ),
        "cors_credentialed_impact": (
            "A malicious site can make authenticated requests as the victim and "
            "read the responses: cross-origin data and session theft."
        ),
        "cors_reflect_title": "CORS: foreign origin reflected",
        "cors_reflect_desc": (
            "Endpoint {url} reflected the probe's foreign origin ('{probe}') in "
            "the 'Access-Control-Allow-Origin' header, without enabling "
            "credentials. Any website can read this endpoint's (unauthenticated) "
            "responses."
        ),
        "cors_reflect_evidence": (
            "GET {url} with 'Origin: {probe}' -> "
            "Access-Control-Allow-Origin: {acao} (credentials not enabled)."
        ),
        "cors_reflect_fix": (
            "Do not reflect the Origin header: allow only an allowlist of trusted "
            "origins and return the exact origin only for those."
        ),
        "cors_reflect_impact": (
            "A third-party site can read this endpoint's responses via the "
            "browser; serious if the endpoint exposes non-public data even "
            "without credentials."
        ),
        "cors_wildcard_title": "CORS: permissive wildcard allow-origin",
        "cors_wildcard_desc": (
            "Endpoint {url} returned 'Access-Control-Allow-Origin: *', letting "
            "any origin read its responses via the browser. With the wildcard, "
            "browsers ignore 'Allow-Credentials: true', so credentialed requests "
            "are not exposed, but unauthenticated data is."
        ),
        "cors_wildcard_evidence": (
            "GET {url} with 'Origin: {probe}' -> "
            "Access-Control-Allow-Origin: * (wildcard)."
        ),
        "cors_wildcard_fix": (
            "Restrict 'Access-Control-Allow-Origin' to an allowlist of trusted "
            "origins instead of the wildcard, especially on endpoints that "
            "expose non-public data."
        ),
        "cors_wildcard_impact": (
            "Any website can read this endpoint's unauthenticated responses via "
            "the browser."
        ),
        # --- open redirect finding (open_redirect_checks.py) ---
        "open_redirect_title": "Open redirect: unvalidated destination",
        "open_redirect_desc": (
            "Endpoint {url} built a redirect to the probe's foreign destination "
            "('{probe}') from a user-controlled parameter, without validating "
            "it: the response carries a 'Location: {location}' header that leads "
            "outside the application. An attacker can redirect the victim to an "
            "arbitrary site."
        ),
        "open_redirect_evidence": (
            "GET {url} (payload = '{probe}') -> redirect response with "
            "'Location: {location}' to the probe's foreign host."
        ),
        "open_redirect_fix": (
            "Do not build the redirect from an unvalidated input value: allow "
            "only destinations relative to your own application or an allowlist "
            "of trusted URLs/hosts; reject absolute or protocol-relative "
            "destinations toward external origins."
        ),
        "open_redirect_impact": (
            "An attacker can use a link on the trusted domain to send the victim "
            "to a convincing phishing site or to steal tokens in OAuth/SSO flows; "
            "it also bypasses domain-based filters."
        ),
        # --- mass assignment finding (mass_assignment_checks.py) ---
        "mass_assignment_title": "Mass assignment: protected field writable by the client",
        "mass_assignment_desc": (
            "The update endpoint {url} accepted a protected field that the "
            "client should not be able to set: sending {field} = {value} "
            "and then re-reading the resource, the field was actually changed. "
            "The application merges the whole request body without filtering "
            "the assignable fields."
        ),
        "mass_assignment_evidence": (
            "Update on {url} with body {{\"{field}\": {value}}} -> re-GET of "
            "the resource shows {field} = {value} (injected value "
            "reflected: write confirmed, not just a 2xx status)."
        ),
        "mass_assignment_fix": (
            "Filter the assignable fields on the server side for updates: use "
            "an explicit allowlist of client-modifiable fields (selective "
            "binding) and reject or ignore any other attribute, especially "
            "role, ownership or internal-state fields."
        ),
        "mass_assignment_impact": (
            "A user can escalate their own privileges or tamper with the "
            "object's state (e.g. become an administrator or change the owner) "
            "by setting fields that should be read-only."
        ),
        # --- missing login rate-limiting finding (ratelimit_checks.py) ---
        "rl_title": "No rate limiting on login",
        "rl_desc": (
            "In {attempts} consecutive failed login attempts against {url}, no "
            "throttling signal was observed (no 429 response and no 'Retry-After' "
            "header). Note: this is an observation over {attempts} attempts, not "
            "absolute proof — a limiter with a higher threshold or an IP-based one "
            "may not have triggered in so few attempts."
        ),
        "rl_evidence": (
            "{attempts} login POSTs with a wrong password against {url}: no 429 "
            "response and no Retry-After header observed."
        ),
        "rl_fix": (
            "Apply rate limiting / progressive backoff on login attempts (per "
            "account and per IP), with temporary lockout after repeated failures "
            "and, where appropriate, a CAPTCHA."
        ),
        "rl_impact": (
            "Without limits, an attacker can brute-force or credential-stuff user "
            "credentials unhindered."
        ),
        # --- verbose error / stack-trace disclosure finding (error_disclosure_checks.py) ---
        "ed_title": "Verbose error / stack trace disclosure",
        "ed_desc": (
            "The request to {url} with a malformed id returned a response (status "
            "{status}) containing a typical stack-trace or framework/ORM error "
            "signature: the application exposes internal details instead of a "
            "generic error. Pattern-based detection (to be confirmed)."
        ),
        "ed_evidence": (
            "GET {url} -> {status}; signature detected: {signature} "
            "(extract: {snippet})."
        ),
        "ed_fix": (
            "Return generic error messages to the client and log details only "
            "server-side; disable debug/stack traces in production."
        ),
        "ed_impact": (
            "An attacker learns the technology, versions, filesystem paths and "
            "internal structure, useful to craft targeted attacks; sometimes query "
            "fragments or data leak."
        ),
        # --- informational discovery finding (cli.py) ---
        "cli_discovery_title": (
            "Additional surface discovered from documentation/source"
        ),
        "cli_discovery_desc": (
            "{count} endpoints were discovered from documentation and/or source "
            "code and added as seeds to the automated scan (only those already "
            "allowed by the allowlist). They widen the surface analyzed by ZAP; "
            "they are not a problem in themselves."
        ),
        "cli_discovery_evidence": "Endpoints added as scan seeds:\n{righe}",
        "cli_discovery_fix": (
            "No action required: this is information about test coverage. Check "
            "that the listed endpoints are the expected ones."
        ),
        "cli_discovery_impact": (
            "No direct impact: an informational note about the tested surface."
        ),
        # --- operator output (cli.py) ---
        "cli_report_written": "Report written to: {path}",
        "cli_error": "Error: {exc}",
        "cli_preflight_failed": (
            "Preflight failed: the environment is not ready for the run."
        ),
    },
}
