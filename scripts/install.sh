#!/bin/sh
# Installazione globale di Gauntlet.
#
# Esegue due operazioni idempotenti (sicure da ripetere):
#   1. installa il pacchetto a livello utente, in modo che il comando
#      `gauntlet` sia disponibile da qualunque progetto;
#   2. registra SKILL.md come skill di Claude Code in
#      ~/.claude/skills/gauntlet/, così è scoperta in ogni progetto.
#
# Prima di installare verifica i prerequisiti (Python >= 3.12, pipx o pip,
# Docker) e avvisa in modo chiaro: non tenta MAI di installare da solo Python
# o Docker. Non richiede privilegi di root e non usa percorsi assoluti fissi:
# la destinazione della skill deriva sempre da $HOME.

set -eu

# Directory del repository (questo script vive in scripts/).
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)

SKILLS_DIR="${HOME}/.claude/skills/gauntlet"

# --- Prerequisito: Python >= 3.12 ------------------------------------------
echo "==> Controllo prerequisiti"
if command -v python3 >/dev/null 2>&1; then
    PY=python3
elif command -v python >/dev/null 2>&1; then
    PY=python
else
    echo "ERRORE: Python non trovato. Gauntlet richiede Python >= 3.12." >&2
    exit 1
fi

if ! "${PY}" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)'; then
    PY_VER=$("${PY}" -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')
    echo "ERRORE: Python >= 3.12 richiesto, trovato ${PY_VER}." >&2
    exit 1
fi
echo "    Python OK ($("${PY}" -c 'import sys; print(".".join(map(str, sys.version_info[:3])))'))"

# --- Prerequisito: pipx oppure pip -----------------------------------------
if command -v pipx >/dev/null 2>&1; then
    INSTALLER=pipx
elif command -v pip >/dev/null 2>&1 || command -v pip3 >/dev/null 2>&1; then
    INSTALLER=pip
else
    echo "ERRORE: né pipx né pip sono disponibili. Installane uno e riprova." >&2
    echo "        (pipx consigliato: https://pipx.pypa.io)" >&2
    exit 1
fi
echo "    Installer disponibile: ${INSTALLER}"

# --- Prerequisito a runtime: Docker (solo avviso, non blocca) --------------
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    echo "    Docker OK (in esecuzione)"
else
    echo "" >&2
    echo "ATTENZIONE: Docker non è installato o non è in esecuzione." >&2
    echo "            L'installazione prosegue, ma Gauntlet NON potrà eseguire" >&2
    echo "            scansioni finché Docker non sarà installato e avviato" >&2
    echo "            (il daemon OWASP ZAP gira in un container)." >&2
    echo "" >&2
fi

# --- Installazione del pacchetto -------------------------------------------
echo "==> Installazione del pacchetto Gauntlet (CLI globale)"
if [ "${INSTALLER}" = "pipx" ]; then
    # --force rende idempotente: reinstalla in modo pulito se già presente.
    pipx install --force "${REPO_DIR}"
    echo "    installato con pipx"
else
    if command -v pip >/dev/null 2>&1; then
        PIP=pip
    else
        PIP=pip3
    fi
    echo "    pipx non trovato: fallback a '${PIP} install --user'"
    # Nota: su distro recenti (PEP 668) pip può rifiutarsi con
    # 'externally-managed-environment'. In tal caso usa pipx (consigliato) oppure,
    # se sai cosa stai facendo, 'pip install --user --break-system-packages'.
    "${PIP}" install --user "${REPO_DIR}"
    echo "    installato con ${PIP} --user"
fi

# --- Registrazione della skill di Claude Code ------------------------------
echo "==> Registrazione della skill di Claude Code"
mkdir -p "${SKILLS_DIR}"
cp "${REPO_DIR}/SKILL.md" "${SKILLS_DIR}/SKILL.md"
echo "    SKILL.md copiato in ${SKILLS_DIR}/SKILL.md"

# --- Verifica che il comando sia raggiungibile nel PATH ---------------------
# `command -v` non interrompe lo script sotto `set -e` perché è il test di un if.
if ! command -v gauntlet >/dev/null 2>&1; then
    echo ""
    echo "ATTENZIONE: il comando 'gauntlet' è stato installato ma non è nel PATH" >&2
    echo "            di questa shell. Per renderlo raggiungibile:" >&2
    echo "              1) esegui 'pipx ensurepath'" >&2
    echo "              2) chiudi e riapri il terminale (o 'source' del profilo)" >&2
    echo "            Poi verifica con 'command -v gauntlet'." >&2
    echo "" >&2
fi

echo ""
echo "Fatto. Il comando 'gauntlet' è installato e la skill è registrata in"
echo "  ${SKILLS_DIR}/"
echo ""
echo "Promemoria:"
echo "  - Docker deve essere in esecuzione: il daemon OWASP ZAP gira in un container."
echo "  - In ogni progetto serve un contratto 'gauntlet.yaml' (vedi gauntlet.example.yaml)"
echo "    e le password degli account esportate come variabili d'ambiente."
echo ""
echo "Se 'gauntlet' non viene trovato subito, assicurati che la cartella bin di"
echo "pipx/pip sia nel PATH (es. 'pipx ensurepath', poi riapri il terminale)."
