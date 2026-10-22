"""Runner di OWASP ZAP: daemon in Docker, client ``zapv2`` e alert normalizzati.

Questo modulo è il "muscolo" che trova le vulnerabilità web classiche
(injection, XSS, header mancanti, misconfigurazioni, path traversal, SSRF, ...).
Pilota un'istanza di ZAP avviata come *daemon* in un container Docker
(immagine ``zaproxy/zap-stable``) tramite il client Python ``zapv2``.

Due responsabilità, tenute separate di proposito:

* :func:`normalize_alert` — funzione **pura** che traduce un alert grezzo di ZAP
  in un :class:`~gauntlet.models.Finding`. È il cuore unit-testato: non tocca
  Docker né la rete, così può essere verificata in isolamento.
* :class:`ZapRunner` — context manager che avvia/arresta il daemon
  (``start()``/``stop()``) e orchestra ``spider``, ``active_scan`` e
  ``alerts`` sul client ``zapv2``.

Scelte di sicurezza (coerenti con il gate di ``gauntlet.safety``):

* **Allowlist fail-closed davanti a tutto.** Ogni operazione che invia traffico
  a un bersaglio (``spider``, ``active_scan``) passa prima per
  :func:`~gauntlet.safety.assert_target_allowed`. Senza contratto configurato il
  controllo non è possibile e l'operazione viene rifiutata (fail-closed).
* **Conferma per lo scan distruttivo.** Uno scan attivo *non* distruttivo gira
  liberamente dopo il check allowlist; uno scan distruttivo
  (``destructive=True``) esige una conferma esplicita a runtime tramite l'hook
  ``confirm`` (vedi :func:`~gauntlet.safety.confirm_destructive`). In assenza di
  via libera si solleva :class:`~gauntlet.safety.DestructiveNotConfirmed`.

Nota di progettazione sulle firme. Il brief fissa
``ZapRunner(api_key: str, port: int = 8080)`` e
``active_scan(target, context_id=None, user_id=None, destructive=False)``. Né
``active_scan`` né il costruttore nella forma documentata hanno un parametro per
il contratto o per l'hook di conferma, ma ``active_scan`` deve chiamare
``assert_target_allowed`` (che richiede un ``Contract``) ed esigere la conferma.
L'unico posto coerente per queste dipendenze è il costruttore: viene quindi
esteso con i parametri opzionali ``contract`` e ``confirm``, mantenendo
invariata la forma minima documentata ``ZapRunner(api_key, port)``. Chi
orchestra (Task 9) costruisce il runner con il contratto caricato e l'hook di
conferma ricevuto dalla CLI.

L'import di ``zapv2`` è *lazy* (dentro i metodi che usano il client): così il
modulo — e in particolare :func:`normalize_alert` — resta importabile e
testabile anche dove il client ZAP non è installato.
"""

from __future__ import annotations

import subprocess
import time
from typing import Any, Callable

from gauntlet.contract import Contract
from gauntlet.models import Finding
from gauntlet.safety import (
    DestructiveNotConfirmed,
    TargetNotAllowed,
    assert_target_allowed,
    confirm_destructive,
)

#: Immagine Docker ufficiale di ZAP usata come daemon.
ZAP_IMAGE = "zaproxy/zap-stable"

#: Mappa il livello di rischio ZAP sulla scala di gravità italiana di Gauntlet.
#: ``critica`` è volutamente assente: è riservata al controllo-accessi confermato
#: (Task 5); ZAP non la produce mai da qui.
_RISK_TO_SEVERITY = {
    "informational": "info",
    "low": "bassa",
    "medium": "media",
    "high": "alta",
}

#: Mappa la confidenza ZAP (stringa) su un float 0.0–1.0 per il :class:`Finding`.
_CONFIDENCE_TO_FLOAT = {
    "false positive": 0.0,
    "low": 0.25,
    "medium": 0.5,
    "high": 0.75,
    "confirmed": 1.0,
    "user confirmed": 1.0,
}

#: Impatto di default se ignorato, per gravità, quando l'alert non ne fornisce.
_IMPACT_BY_SEVERITY = {
    "info": "Informativo: nessun impatto diretto, utile per l'hardening.",
    "bassa": "Impatto limitato; da correggere nella normale manutenzione.",
    "media": "Possibile abuso in combinazione con altri difetti o accessi.",
    "alta": "Sfruttabile per compromettere dati o funzioni dell'applicazione.",
}


def normalize_alert(raw: dict[str, Any]) -> Finding:
    """Converte un alert grezzo di ZAP in un :class:`Finding` normalizzato.

    Mappa il rischio ZAP (``Informational``/``Low``/``Medium``/``High``, in modo
    case-insensitive) sulla gravità italiana (``info``/``bassa``/``media``/
    ``alta``). Un rischio sconosciuto o assente degrada a ``info`` (scelta
    prudente: non si gonfia mai la gravità). Non viene mai emessa ``critica``,
    riservata al controllo-accessi confermato (Task 5).

    Trasporta i campi dell'alert: ``name`` → titolo, ``description``,
    ``solution`` → ``fix``, ``url`` ed ``evidence``. ``confidence`` (stringa ZAP)
    è tradotta in float; ``impact_if_ignored`` usa ``otherinfo`` se presente,
    altrimenti un default per gravità.
    """
    risk = str(raw.get("risk", "")).strip().lower()
    severity = _RISK_TO_SEVERITY.get(risk, "info")

    confidence_raw = str(raw.get("confidence", "")).strip().lower()
    confidence = _CONFIDENCE_TO_FLOAT.get(confidence_raw, 0.5)

    url = raw.get("url") or None
    impact = raw.get("otherinfo") or _IMPACT_BY_SEVERITY[severity]

    return Finding(
        source="zap",
        severity=severity,
        title=raw.get("name", ""),
        description=raw.get("description", ""),
        evidence=raw.get("evidence", ""),
        fix=raw.get("solution", ""),
        impact_if_ignored=impact,
        confidence=confidence,
        url=url,
    )


class ZapRunner:
    """Context manager che pilota un daemon ZAP in Docker via il client ``zapv2``.

    Uso tipico::

        with ZapRunner(api_key, contract=contract, confirm=hook) as zap:
            zap.spider("http://localhost:8081/")
            zap.active_scan("http://localhost:8081/", destructive=True)
            findings = zap.alerts("http://localhost:8081")

    :param api_key: chiave API con cui si avvia il daemon e si autentica il client.
    :param port: porta su cui ZAP espone l'API/proxy (default ``8080``).
    :param contract: contratto di progetto; serve a ``spider``/``active_scan``
        per il check allowlist. Senza di esso quelle operazioni falliscono
        fail-closed.
    :param confirm: hook di conferma per i passi distruttivi (vedi
        :func:`~gauntlet.safety.confirm_destructive`).
    """

    def __init__(
        self,
        api_key: str,
        port: int = 8080,
        *,
        contract: Contract | None = None,
        confirm: Callable[[str], bool] | None = None,
    ) -> None:
        self.api_key = api_key
        self.port = port
        self._contract = contract
        self._confirm = confirm
        #: Client ``zapv2.ZAPv2``, creato da :meth:`start`. ``None`` finché non avviato.
        self._zap: Any = None
        #: ID del container Docker avviato, per poterlo arrestare.
        self._container_id: str | None = None
        #: Intervallo (s) tra i poll di stato di spider/active scan.
        self._poll_interval: float = 2.0
        #: Timeout (s) di attesa che il daemon ZAP sia pronto dopo l'avvio.
        self._ready_timeout: float = 120.0

    # --- ciclo di vita del daemon ---------------------------------------

    def _build_docker_command(self) -> list[str]:
        """Costruisce il comando ``docker run`` che avvia il daemon ZAP.

        Include ``--add-host=host.docker.internal:host-gateway`` così un
        bersaglio su ``localhost`` dell'host è raggiungibile dal container.

        Il daemon viene avviato con ``-silent`` e con i flag di configurazione
        ``autoupdate.*``/``start.checkForUpdates`` a ``false`` per **impedire il
        controllo/installazione automatica di add-on all'avvio**: quell'auto-update
        riavvierebbe il daemon a metà scan, facendo cadere la connessione del
        client ``zapv2`` (``RemoteDisconnected`` / "Unable to connect to proxy").
        """
        return [
            "docker",
            "run",
            "-d",  # detached: restituisce l'ID del container
            "--rm",  # rimosso allo stop
            "--add-host=host.docker.internal:host-gateway",
            "-p",
            f"{self.port}:{self.port}",
            ZAP_IMAGE,
            "zap.sh",
            "-daemon",
            # Nessun update-check automatico né invio statistiche: evita che il
            # daemon installi add-on e si riavvii durante lo scan.
            "-silent",
            "-host",
            "0.0.0.0",
            "-port",
            str(self.port),
            "-config",
            "api.addrs.addr.name=.*",
            "-config",
            "api.addrs.addr.regex=true",
            "-config",
            f"api.key={self.api_key}",
            # Belt-and-suspenders: disabilita esplicitamente ogni forma di
            # auto-update/installazione all'avvio, in aggiunta a -silent.
            "-config",
            "autoupdate.checkOnStart=false",
            "-config",
            "autoupdate.downloadNewRelease=false",
            "-config",
            "autoupdate.installAddonUpdates=false",
            "-config",
            "autoupdate.installScannerRules=false",
            "-config",
            "start.checkForUpdates=false",
        ]

    def start(self) -> None:
        """Avvia il daemon ZAP in Docker e connette il client ``zapv2``.

        Lancia il container, attende che l'API risponda e inizializza il client.
        Solleva :class:`RuntimeError` se il daemon non diventa pronto entro il
        timeout.
        """
        result = subprocess.run(
            self._build_docker_command(),
            capture_output=True,
            text=True,
            check=True,
        )
        self._container_id = result.stdout.strip()

        # Import lazy: il client ZAP serve solo a runtime, non all'import del modulo.
        from zapv2 import ZAPv2

        proxy = f"http://localhost:{self.port}"
        self._zap = ZAPv2(
            apikey=self.api_key,
            proxies={"http": proxy, "https": proxy},
        )
        self._await_ready()

    def _await_ready(self) -> None:
        """Attende che l'API del daemon risponda, entro ``_ready_timeout``."""
        deadline = time.monotonic() + self._ready_timeout
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                self._zap.core.version
                return
            except Exception as exc:  # il daemon non è ancora in ascolto
                last_error = exc
                time.sleep(self._poll_interval)
        raise RuntimeError(
            f"Il daemon ZAP non è diventato pronto entro {self._ready_timeout:.0f}s."
        ) from last_error

    def stop(self) -> None:
        """Arresta (e, grazie a ``--rm``, rimuove) il container ZAP, se avviato."""
        if self._container_id:
            subprocess.run(
                ["docker", "stop", self._container_id],
                capture_output=True,
                text=True,
            )
            self._container_id = None
        self._zap = None

    def __enter__(self) -> "ZapRunner":
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    # --- accessori pubblici ----------------------------------------------

    @property
    def client(self) -> Any:
        """Client ``zapv2`` vivo, da passare a chi richiede il client grezzo.

        È l'accessore pubblico che la CLI usa per :func:`build_zap_context`
        (che lavora direttamente su ``zap.context`` / ``zap.authentication`` /
        ``zap.users`` / ``zap.script``). Solleva :class:`RuntimeError` se il
        runner non è avviato, esattamente come :meth:`_require_client`.
        """
        return self._require_client()

    # --- helper interni --------------------------------------------------

    def _assert_allowed(self, target: str) -> None:
        """Verifica l'allowlist per ``target`` (fail-closed senza contratto)."""
        if self._contract is None:
            raise TargetNotAllowed(
                "Nessun contratto configurato: impossibile verificare "
                f"l'allowlist per {target!r} (fail-closed)."
            )
        assert_target_allowed(self._contract, target)

    def _require_client(self) -> Any:
        if self._zap is None:
            raise RuntimeError("ZapRunner non avviato: chiama start() (o usa 'with').")
        return self._zap

    def _await_scan(self, status_fn: Callable[[Any], Any], scan_id: Any) -> None:
        """Attende il completamento di uno scan interrogandone lo stato (0–100)."""
        while True:
            status = status_fn(scan_id)
            try:
                percent = int(status)
            except (TypeError, ValueError):
                # Stato non numerico (es. scan terminato/sconosciuto): non bloccare.
                return
            if percent >= 100:
                return
            time.sleep(self._poll_interval)

    # --- operazioni ------------------------------------------------------

    def spider(
        self,
        target: str,
        context_id: int | None = None,
        user_id: int | None = None,
    ) -> None:
        """Esegue lo *spider* (crawling) di ``target`` e ne attende il termine.

        Operazione di sola lettura, ma invia comunque traffico al bersaglio:
        passa quindi per il check allowlist. Con ``context_id`` e ``user_id`` fa
        crawling come utente autenticato.
        """
        self._assert_allowed(target)
        zap = self._require_client()
        if context_id is not None and user_id is not None:
            scan_id = zap.spider.scan_as_user(context_id, user_id, target)
        else:
            scan_id = zap.spider.scan(target)
        self._await_scan(zap.spider.status, scan_id)

    def active_scan(
        self,
        target: str,
        context_id: int | None = None,
        user_id: int | None = None,
        destructive: bool = False,
    ) -> None:
        """Esegue lo scan attivo di ``target`` e ne attende il termine.

        Ordine delle garanzie di sicurezza, **prima di qualunque traffico**:

        1. check allowlist (:meth:`_assert_allowed`) — fail-closed;
        2. se ``destructive``, conferma esplicita via l'hook ``confirm``: in
           assenza di via libera si solleva :class:`DestructiveNotConfirmed`.
           Se l'hook solleva, l'eccezione propaga (non viene inghiottita).

        Uno scan *non* distruttivo gira liberamente dopo il passo 1. Con
        ``context_id`` e ``user_id`` scansiona come utente autenticato.
        """
        # 1) Allowlist davanti a tutto, anche prima della conferma.
        self._assert_allowed(target)

        # 2) Gate distruttivo.
        if destructive:
            description = f"Active scan distruttivo su {target}"
            if not confirm_destructive(description, self._confirm):
                raise DestructiveNotConfirmed(
                    f"Scan distruttivo non confermato per {target!r}: "
                    "nessun via libera esplicito."
                )

        zap = self._require_client()
        if context_id is not None and user_id is not None:
            scan_id = zap.ascan.scan_as_user(target, context_id, user_id)
        else:
            scan_id = zap.ascan.scan(target)
        self._await_scan(zap.ascan.status, scan_id)

    def alerts(self, base_url: str) -> list[Finding]:
        """Restituisce gli alert di ZAP per ``base_url`` come :class:`Finding`.

        Legge gli alert dal client (``core.alerts``) e li normalizza tutti con
        :func:`normalize_alert`.
        """
        zap = self._require_client()
        raw_alerts = zap.core.alerts(baseurl=base_url)
        return [normalize_alert(raw) for raw in raw_alerts]
