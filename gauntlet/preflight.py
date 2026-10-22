"""Preflight di Gauntlet: l'ambiente è pronto e gli account di prova esistono?

Prima di qualunque run la skill deve sapere se può operare:

* **Docker presente e immagine ZAP tirabile** — il motore di scansione
  (:mod:`gauntlet.zap_runner`) gira come daemon in un container; senza Docker o
  senza l'immagine non c'è nulla da fare.
* **Target raggiungibili** — ogni voce di ``allowed_targets`` deve rispondere
  secondo la modalità di raggiungibilità dichiarata nel contratto
  (``reachability``: es. ``localhost``, ``docker``, ``vpn``).
* **Account di prova seminati** — ai livelli autenticati (vedi
  :func:`gauntlet.levels.actions_for`) servono i due account di clienti diversi
  descritti nel contratto. Se non esistono, il preflight **non li crea**: la
  creazione, quando possibile, è un passo che Claude esegue previa
  autorizzazione dell'utente, *fuori* da questa funzione. Qui ci limitiamo a
  produrre una *guida* (``account_guidance``) che spiega quali account servono,
  con quali permessi e con quali dati noti, attingendo a docs/src del contratto.

**Funzione pura.** :func:`run` non tocca Docker, la rete o l'applicazione: le
tre verifiche con effetti collaterali (``docker_check``, ``reachability_check``,
``account_probe``) sono iniettate come callable. Quando non vengono passate,
:func:`run` usa i controlli reali di default (vedi le ``_default_*`` sotto), che
restano l'unico punto in cui avvengono I/O. Questo rende il cuore decisionale
interamente verificabile in isolamento.

Nota sulle firme (per l'adjudicator del controller). Il brief nomina come
iniettabili solo ``docker_check`` e ``account_probe``. Ma il preflight deve
anche verificare la raggiungibilità dei target, e farlo in modo *puro* impone di
iniettare pure quel controllo: è stato quindi aggiunto un terzo callable
opzionale ``reachability_check`` con un default reale, coerente con il pattern
dei primi due. Nessuna delle firme del brief cambia: ``docker_check()`` e
``account_probe(account)`` restano identici.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

from gauntlet.contract import Account, Contract, resolve_password
from gauntlet.levels import actions_for
from gauntlet.safety import TargetNotAllowed, assert_target_allowed, host_side_url

#: Firma del controllo Docker: nessun argomento, ``True`` se Docker è presente e
#: l'immagine ZAP è tirabile.
DockerCheck = Callable[[], bool]

#: Firma del controllo di raggiungibilità: riceve il target e la modalità
#: ``reachability`` dichiarata nel contratto, ``True`` se il target risponde.
ReachabilityCheck = Callable[[str, str], bool]

#: Firma della sonda account: riceve un :class:`Account`, ``True`` se l'account
#: di prova esiste già nell'applicazione sotto test.
AccountProbe = Callable[[Account], bool]

#: Timeout (secondi) per i controlli reali di default, tenuti brevi apposta.
_DOCKER_INFO_TIMEOUT = 20
_DOCKER_PULL_TIMEOUT = 600
_REACHABILITY_TIMEOUT = 5.0


@dataclass
class PreflightResult:
    """Esito del preflight.

    Attributi:
        ok: ``True`` solo se l'ambiente è pronto *e* non manca nulla (nessun
            problema e, ai livelli autenticati, account presenti).
        problems: elenco leggibile dei problemi riscontrati (vuoto se ``ok``).
        account_guidance: istruzioni su quali account creare e con quali
            permessi/dati, oppure ``None`` se non servono (livello non
            autenticato) o gli account esistono già.
    """

    ok: bool
    problems: list[str]
    account_guidance: str | None


def _default_docker_check() -> bool:
    """Controllo reale: Docker presente e immagine ZAP tirabile.

    Verifica che il binario ``docker`` esista, che il daemon risponda
    (``docker info``) e che l'immagine ZAP sia scaricabile (``docker pull``).
    Qualunque errore di ambiente si traduce in ``False`` (fail-closed): è il
    preflight, non deve mai sollevare.
    """
    # Import locale per non legare l'import del modulo a zap_runner.
    from gauntlet.zap_runner import ZAP_IMAGE

    docker = shutil.which("docker")
    if docker is None:
        return False
    try:
        info = subprocess.run(
            [docker, "info"],
            capture_output=True,
            timeout=_DOCKER_INFO_TIMEOUT,
        )
        if info.returncode != 0:
            return False
        pull = subprocess.run(
            [docker, "pull", ZAP_IMAGE],
            capture_output=True,
            timeout=_DOCKER_PULL_TIMEOUT,
        )
        return pull.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _default_reachability_check(target: str, reachability: str) -> bool:
    """Controllo reale di raggiungibilità: una connessione TCP al target.

    ``reachability`` è la modalità dichiarata nel contratto (es. ``localhost``,
    ``docker``, ``vpn``): è un'indicazione di *come* il target è raggiungibile;
    la verifica concreta è un tentativo di connessione a host:porta estratti dal
    target. Qualunque errore ⇒ ``False`` (il target è considerato irraggiungibile).

    In modalità ``docker`` un host ``host.docker.internal`` (usato da ZAP nel
    container) non risolve sul processo host: la sonda lo rimappa su
    ``127.0.0.1`` per la sola connessione host-side via
    :func:`gauntlet.safety.host_side_url`. Il gate allowlist in :func:`run` resta
    valutato sul target originale.
    """
    parts = urlsplit(host_side_url(target, reachability))
    host = parts.hostname
    if not host:
        return False
    port = parts.port
    if port is None:
        port = {"http": 80, "https": 443}.get(parts.scheme.lower())
    if port is None:
        return False
    try:
        with socket.create_connection((host, port), timeout=_REACHABILITY_TIMEOUT):
            return True
    except OSError:
        return False


def _make_default_account_probe(contract: Contract) -> AccountProbe:
    """Costruisce la sonda account reale legata al ``contract``.

    La sola verifica onesta che un account *esista* nell'applicazione è provare
    ad autenticarsi: la sonda tenta il login con la password risolta dalla
    variabile d'ambiente del contratto e restituisce ``True`` se riesce. Se la
    password non è configurata, il login fallisce o il client HTTP non è
    disponibile, restituisce ``False`` (account considerato assente). Non ha mai
    effetti distruttivi.
    """

    def probe(account: Account) -> bool:
        try:
            # Import locale: tiene preflight importabile anche senza httpx.
            from gauntlet.authn import LoginFailed, login

            password = resolve_password(account)
            # Gate allowlist fail-closed: se l'URL di login non è in
            # ``allowed_targets``, login solleva TargetNotAllowed e non invia
            # nulla; la except sotto lo tratta come account assente.
            login(
                contract.login,
                account.username,
                password,
                allowed_targets=contract.allowed_targets,
                reachability=contract.reachability,
            )
            return True
        except Exception:
            # Qualunque fallimento (login, password mancante, rete) ⇒ assente.
            return False

    return probe


def _account_guidance(contract: Contract, missing: list[Account]) -> str:
    """Compone la guida alla creazione degli account mancanti.

    Descrive, per ciascun account mancante: etichetta, username, ambito di
    isolamento (``tenant_id``, i *permessi* attesi) e i dati noti seminati
    (risorse con ``kind``/``id``/URL e marcatore). Cita i percorsi di
    documentazione e sorgente del contratto quando presenti, perché è lì che si
    trovano i permessi esatti da assegnare.
    """
    righe: list[str] = []
    righe.append(
        "Account di prova mancanti: creali prima di eseguire i livelli "
        "autenticati. Gauntlet NON li crea da solo."
    )
    righe.append(
        "Servono due account di clienti diversi, ciascuno con i propri permessi "
        "(isolamento tra tenant) e con i dati noti seminati elencati sotto."
    )
    for acc in missing:
        tenant = acc.tenant_id or "(nessun tenant dichiarato)"
        righe.append("")
        righe.append(f"- Account '{acc.label}':")
        righe.append(f"    username: {acc.username}")
        righe.append(
            f"    password: nella variabile d'ambiente {acc.password_env} "
            "(mai nel contratto)"
        )
        righe.append(
            f"    permessi/isolamento: appartiene al tenant {tenant}; deve poter "
            "accedere SOLO alle proprie risorse."
        )
        if acc.seeded_resources:
            righe.append("    dati noti da seminare:")
            for res in acc.seeded_resources:
                marker = (
                    f", marcatore '{res.seed_marker}'"
                    if res.seed_marker
                    else ""
                )
                righe.append(
                    f"      · {res.kind} id={res.id} "
                    f"(URL {res.url_template}{marker})"
                )
        else:
            righe.append("    dati noti da seminare: nessuno dichiarato.")

    riferimenti = []
    if contract.docs_path:
        riferimenti.append(f"documentazione in {contract.docs_path}")
    if contract.src_path:
        riferimenti.append(f"sorgente in {contract.src_path}")
    if riferimenti:
        righe.append("")
        righe.append(
            "Per i permessi e i ruoli esatti da assegnare consulta "
            + " e ".join(riferimenti)
            + "."
        )
    return "\n".join(righe)


def run(
    contract: Contract,
    level: int,
    docker_check: DockerCheck | None = None,
    account_probe: AccountProbe | None = None,
    reachability_check: ReachabilityCheck | None = None,
) -> PreflightResult:
    """Verifica che l'ambiente e gli account siano pronti per un run al dato livello.

    Controlla, nell'ordine: (1) Docker presente e immagine ZAP tirabile; (2) ogni
    ``allowed_targets`` raggiungibile secondo ``contract.reachability``; (3) ai
    livelli autenticati (``actions_for(level).authenticated``), se gli account
    seminati non esistono (via ``account_probe``) produce ``account_guidance``.

    I tre controlli con effetti collaterali sono iniettabili; se omessi usa i
    controlli reali di default. La funzione è **pura** rispetto agli argomenti
    iniettati e non crea mai account né invia traffico di attacco.

    Args:
        contract: il contratto di progetto validato.
        level: livello di conoscenza dell'attaccante (1–4).
        docker_check: ``() -> bool``; default: controllo reale di Docker/ZAP.
        account_probe: ``(Account) -> bool``; default: tentativo di login reale.
        reachability_check: ``(target, reachability) -> bool``; default: TCP.

    Returns:
        Il :class:`PreflightResult` con esito, problemi e guida account.
    """
    if docker_check is None:
        docker_check = _default_docker_check
    if reachability_check is None:
        reachability_check = _default_reachability_check
    if account_probe is None:
        account_probe = _make_default_account_probe(contract)

    problems: list[str] = []

    # (1) Docker + immagine ZAP.
    if not docker_check():
        problems.append(
            "Docker non disponibile o immagine ZAP non tirabile: avvia Docker e "
            "assicurati di poter scaricare l'immagine di OWASP ZAP."
        )

    # (2) Raggiungibilità di ogni target consentito. Prima il gate fail-closed:
    #     non si sonda mai un'origine fuori allowlist, nemmeno in preflight.
    for target in contract.allowed_targets:
        try:
            assert_target_allowed(contract, target)
        except TargetNotAllowed as exc:
            problems.append(f"Target non in allowlist: {exc}")
            continue
        if not reachability_check(target, contract.reachability):
            problems.append(
                f"Target non raggiungibile ({contract.reachability}): {target}."
            )

    # (3) Account di prova, solo ai livelli autenticati.
    account_guidance: str | None = None
    if actions_for(level).authenticated:
        missing = [acc for acc in contract.accounts if not account_probe(acc)]
        if missing:
            account_guidance = _account_guidance(contract, missing)
            etichette = ", ".join(acc.label for acc in missing)
            problems.append(
                f"Account di prova mancanti per il livello autenticato: {etichette} "
                "(vedi account_guidance)."
            )

    ok = not problems and account_guidance is None
    return PreflightResult(ok=ok, problems=problems, account_guidance=account_guidance)
