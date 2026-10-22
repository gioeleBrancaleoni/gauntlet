"""Test del modulo di debolezze JWT (``gauntlet.jwt_checks``).

Due debolezze classiche, verificate in modo deterministico contro un server
finto (``pytest-httpserver``):

* **alg=none accettato** — un token forgiato con header ``{"alg":"none"}`` e
  firma vuota, stessa payload del token reale, viene inviato alla probe URL. Se
  il server risponde ``2xx`` e il corpo contiene il marcatore atteso, il server
  ha accettato un token non firmato: finding ``critica``.
* **secret HMAC debole** — solo per alg ``HS*``, la firma del token reale è
  rigiocata contro una piccola wordlist di segreti comuni; se uno riproduce la
  firma, il segreto è indovinabile: finding ``critica``. Per ``RS*``/``none`` il
  controllo è saltato (non applicabile).

Il gate allowlist fail-closed è sempre la prima barriera: una probe URL fuori
allowlist non deve produrre alcuna richiesta.
"""

import base64
import hashlib
import hmac
import json

import httpx
import pytest
from werkzeug.wrappers import Response

from gauntlet import jwt_checks
from gauntlet.contract import Account, Contract, LoginConfig
from gauntlet.i18n import t

MARKER = "JWT-SEED-MARKER"
_HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _segment(obj: dict) -> str:
    return _b64(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def _hmac_token(payload: dict, secret: str, alg: str = "HS256") -> str:
    header = {"alg": alg, "typ": "JWT"}
    signing_input = f"{_segment(header)}.{_segment(payload)}"
    sig = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), _HASHES[alg])
    return f"{signing_input}.{_b64(sig.digest())}"


def _rs256_token(payload: dict) -> str:
    header = {"alg": "RS256", "typ": "JWT"}
    # Firma fittizia: il modulo non deve tentare di validarla (RS* => skip).
    return f"{_segment(header)}.{_segment(payload)}.{_b64(b'not-a-real-signature')}"


def _contract(allowed_targets: list[str]) -> Contract:
    return Contract(
        name="test",
        allowed_targets=allowed_targets,
        reachability="localhost",
        login=LoginConfig(
            method="token",
            login_url="http://localhost/login",
            username_field="email",
            password_field="password",
            logged_in_indicator='"token"',
            token_path="token",
        ),
        accounts=[Account(label="a", username="a@x", password_env="A_PW")],
    )


def _run(httpserver, token: str, *, allowed: list[str] | None = None, lang: str = "it"):
    probe = httpserver.url_for("/probe")
    allowed_targets = allowed if allowed is not None else [httpserver.url_for("/")]
    return jwt_checks.run(
        token=token,
        probe_url=probe,
        marker=MARKER,
        session_headers={"Authorization": f"Bearer {token}"},
        contract=_contract(allowed_targets),
        reachability="localhost",
        lang=lang,
    )


def _alg_header(auth: str) -> str | None:
    """Estrae l'``alg`` dall'header del bearer in ``Authorization``, o ``None``."""
    token = auth[len("Bearer ") :] if auth.startswith("Bearer ") else ""
    header_seg = token.split(".")[0] if token else ""
    try:
        padding = "=" * (-len(header_seg) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_seg + padding))
    except Exception:
        return None
    return header.get("alg") if isinstance(header, dict) else None


def _alg_none_vuln_handler(request):
    """Server con vera vulnerabilità alg=none: verifica le firme (rifiuta un
    token a firma corrotta, alg HS*) MA accetta i token ``alg=none`` a firma
    vuota. È il controllo negativo a distinguerlo da un endpoint non autenticato.
    """
    alg = _alg_header(request.headers.get("Authorization", ""))
    if isinstance(alg, str) and alg.lower() == "none":
        return Response(
            f'{{"data": "{MARKER}"}}', status=200, content_type="application/json"
        )
    # Qualsiasi altra firma (incluso il controllo negativo HS* corrotto) => 401.
    return Response("unauthorized", status=401)


def test_alg_none_accepted_is_critical(httpserver):
    # Vera vulnerabilità alg=none: il controllo negativo (firma corrotta) è
    # RIFIUTATO (il server verifica le firme) ma il token alg=none a firma vuota
    # è ACCETTATO col marcatore => critica alg=none.
    httpserver.expect_request("/probe", method="GET").respond_with_handler(
        _alg_none_vuln_handler
    )
    token = _hmac_token({"sub": "user-1", "role": "admin"}, "una-chiave-robusta-xyz")

    findings = _run(httpserver, token)

    alg_none = [f for f in findings if "alg=none" in f.title]
    assert alg_none
    assert alg_none[0].severity == "critica"
    # Nessun finding "morbido" di firma non verificata: il controllo era rifiutato.
    assert not any(f.title == t("it", "jwt_unverified_title") for f in findings)


def test_control_transport_error_skips_alg_none(httpserver, monkeypatch):
    # Residuo FP: se il controllo negativo FALLISCE a livello di trasporto
    # (_request_forged -> None), l'oracolo non è stabilito. Un fallimento del
    # controllo NON deve essere scambiato per un rifiuto: anche se una richiesta
    # alg=none sarebbe accettata, non si emette né la critica alg=none né il
    # finding morbido. Fail-closed, coerente con l'IDOR sequenziale.
    accepted = httpx.Response(200, text=f'{{"data": "{MARKER}"}}')

    def fake_forged(probe_url, forged_token, session_headers, reachability):
        # I token alg=none hanno firma VUOTA (terminano con '.'); il token di
        # controllo ha una firma corrotta (non termina con '.'). Simula un errore
        # di trasporto SOLO sul controllo, accettando invece le varianti alg=none.
        if forged_token.endswith("."):
            return accepted
        return None

    monkeypatch.setattr(jwt_checks, "_request_forged", fake_forged)
    httpserver.expect_request("/probe", method="GET").respond_with_data(
        f'{{"data": "{MARKER}"}}', content_type="application/json"
    )
    token = _hmac_token({"sub": "user-1"}, "una-chiave-robusta-xyz")

    findings = _run(httpserver, token)

    assert not any("alg=none" in f.title for f in findings)
    assert not any(f.title == t("it", "jwt_unverified_title") for f in findings)
    assert findings == []


def test_unverified_signature_when_control_also_accepted(httpserver):
    # Endpoint che accetta QUALUNQUE token (anche il controllo negativo a firma
    # corrotta): non verifica affatto la firma / non autenticato. NON deve essere
    # etichettato alg=none; emette il finding morbido 'alta' (0.6).
    httpserver.expect_request("/probe", method="GET").respond_with_data(
        f'{{"data": "{MARKER}"}}', content_type="application/json"
    )
    token = _hmac_token({"sub": "user-1", "role": "admin"}, "una-chiave-robusta-xyz")

    findings = _run(httpserver, token)

    assert not any("alg=none" in f.title for f in findings)
    soft = [f for f in findings if f.title == t("it", "jwt_unverified_title")]
    assert len(soft) == 1
    assert soft[0].severity == "alta"
    assert soft[0].confidence == 0.6


def test_alg_none_rejected_no_finding(httpserver):
    # Server corretto: il token forgiato non firmato è rifiutato (401).
    httpserver.expect_request("/probe", method="GET").respond_with_data(
        "unauthorized", status=401
    )
    token = _hmac_token({"sub": "user-1"}, "una-chiave-robusta-xyz")

    findings = _run(httpserver, token)

    assert not any("alg=none" in f.title for f in findings)


def test_weak_hmac_secret_named(httpserver):
    # Forgiato rifiutato (niente alg=none); il token reale è firmato con "secret",
    # che è nella wordlist => finding del secret debole, che nomina il segreto.
    httpserver.expect_request("/probe", method="GET").respond_with_data(
        "unauthorized", status=401
    )
    token = _hmac_token({"sub": "user-1"}, "secret")

    findings = _run(httpserver, token)

    weak = [f for f in findings if f.severity == "critica" and "secret" in f.title.lower()]
    assert weak
    assert "secret" in weak[0].description


def test_strong_hmac_secret_no_finding(httpserver):
    httpserver.expect_request("/probe", method="GET").respond_with_data(
        "unauthorized", status=401
    )
    token = _hmac_token({"sub": "user-1"}, "9f3b2c1d-robusto-e-lungo-non-indovinabile")

    findings = _run(httpserver, token)

    assert findings == []


def test_rs256_skips_weak_secret_check(httpserver):
    httpserver.expect_request("/probe", method="GET").respond_with_data(
        "unauthorized", status=401
    )
    token = _rs256_token({"sub": "user-1"})

    # Non deve sollevare e non deve produrre un finding di secret debole.
    findings = _run(httpserver, token)

    assert findings == []


def test_malformed_token_returns_empty(httpserver):
    httpserver.expect_request("/probe", method="GET").respond_with_data(
        f'{{"data": "{MARKER}"}}', content_type="application/json"
    )

    assert jwt_checks.run(
        token="questo-non-e-un-jwt",
        probe_url=httpserver.url_for("/probe"),
        marker=MARKER,
        session_headers={},
        contract=_contract([httpserver.url_for("/")]),
        reachability="localhost",
    ) == []


def test_off_allowlist_probe_sends_no_request(httpserver):
    # La probe URL non è coperta dall'allowlist => nessuna richiesta deve partire.
    handler_hits: list[str] = []

    def handler(request):
        handler_hits.append(request.path)
        return Response(f'{{"data": "{MARKER}"}}', status=200)

    httpserver.expect_request("/probe", method="GET").respond_with_handler(handler)
    token = _hmac_token({"sub": "user-1"}, "secret")

    findings = _run(httpserver, token, allowed=["http://altro-host-non-consentito:9999"])

    assert findings == []
    assert handler_hits == []


def test_alg_none_capitalized_variant_accepted_is_flagged(httpserver):
    # Server che accetta SOLO la variante capitalizzata 'None' (match
    # case-sensitive su una forma non-lowercase): la variante lowercase 'none'
    # viene rifiutata, ma il broadening prova anche 'None' => comunque segnalato,
    # con un solo finding che annota la variante nell'evidenza.
    def handler(request):
        auth = request.headers.get("Authorization", "")
        token = auth[len("Bearer ") :] if auth.startswith("Bearer ") else ""
        header_seg = token.split(".")[0] if token else ""
        try:
            padding = "=" * (-len(header_seg) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_seg + padding))
        except Exception:
            header = {}
        if isinstance(header, dict) and header.get("alg") == "None":
            return Response(
                f'{{"data": "{MARKER}"}}', status=200, content_type="application/json"
            )
        return Response("unauthorized", status=401)

    httpserver.expect_request("/probe", method="GET").respond_with_handler(handler)
    # Token reale HS256 con segreto robusto: niente finding di secret debole.
    token = _hmac_token({"sub": "user-1", "role": "admin"}, "una-chiave-robusta-xyz")

    findings = _run(httpserver, token)

    alg_none = [f for f in findings if "alg=none" in f.title]
    assert len(alg_none) == 1
    assert alg_none[0].severity == "critica"
    # L'evidenza annota quale variante ha funzionato.
    assert "'alg: None'" in alg_none[0].evidence


def test_alg_none_finding_localized_english(httpserver):
    # Vera vulnerabilità alg=none (controllo negativo rifiutato): finding in EN.
    httpserver.expect_request("/probe", method="GET").respond_with_handler(
        _alg_none_vuln_handler
    )
    token = _hmac_token({"sub": "user-1"}, "una-chiave-robusta-xyz")

    findings = _run(httpserver, token, lang="en")

    alg_none = [f for f in findings if "alg=none" in f.title]
    assert alg_none
    assert "accepted" in alg_none[0].title.lower()
