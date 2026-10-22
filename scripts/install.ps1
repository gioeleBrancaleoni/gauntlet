# Installazione globale di Gauntlet su Windows nativo (PowerShell).
#
# Equivalente di scripts/install.sh. Esegue due operazioni idempotenti:
#   1. installa il pacchetto a livello utente (comando `gauntlet` sul PATH);
#   2. registra SKILL.md come skill di Claude Code in
#      %USERPROFILE%\.claude\skills\gauntlet\, scoperta in ogni progetto.
#
# Verifica i prerequisiti (Python >= 3.12, pipx o pip, Docker) e avvisa in modo
# chiaro: non installa MAI da solo Python o Docker.
#
# Uso (senza modificare la policy di sistema):
#   powershell -ExecutionPolicy Bypass -File scripts\install.ps1

$ErrorActionPreference = 'Stop'

# Radice del repository (questo script vive in scripts\).
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoDir = (Resolve-Path (Join-Path $ScriptDir '..')).Path

$SkillsDir = Join-Path $env:USERPROFILE '.claude\skills\gauntlet'

Write-Host '==> Controllo prerequisiti'

# --- Prerequisito: Python >= 3.12 ------------------------------------------
# Preferisce il launcher `py -3`, poi `python`.
$PyCmd = $null
$PyArgs = @()
if (Get-Command py -ErrorAction SilentlyContinue) {
    $PyCmd = 'py'
    $PyArgs = @('-3')
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $PyCmd = 'python'
    $PyArgs = @()
} else {
    Write-Error 'Python non trovato. Gauntlet richiede Python >= 3.12.'
    exit 1
}

$verCheck = @($PyArgs + @('-c', 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)'))
& $PyCmd @verCheck
if ($LASTEXITCODE -ne 0) {
    $ver = (& $PyCmd @($PyArgs + @('-c', 'import sys; print(".".join(map(str, sys.version_info[:3])))'))).Trim()
    Write-Error "Python >= 3.12 richiesto, trovato $ver."
    exit 1
}
$ver = (& $PyCmd @($PyArgs + @('-c', 'import sys; print(".".join(map(str, sys.version_info[:3])))'))).Trim()
Write-Host "    Python OK ($ver)"

# --- Prerequisito: pipx oppure pip -----------------------------------------
$Installer = $null
if (Get-Command pipx -ErrorAction SilentlyContinue) {
    $Installer = 'pipx'
} elseif ((Get-Command pip -ErrorAction SilentlyContinue) -or (Get-Command pip3 -ErrorAction SilentlyContinue)) {
    $Installer = 'pip'
} else {
    Write-Error 'Né pipx né pip sono disponibili. Installane uno e riprova (pipx consigliato: https://pipx.pypa.io).'
    exit 1
}
Write-Host "    Installer disponibile: $Installer"

# --- Prerequisito a runtime: Docker (solo avviso, non blocca) --------------
$dockerOk = $false
if (Get-Command docker -ErrorAction SilentlyContinue) {
    try {
        docker info *> $null
        if ($LASTEXITCODE -eq 0) { $dockerOk = $true }
    } catch {
        $dockerOk = $false
    }
}
if ($dockerOk) {
    Write-Host '    Docker OK (in esecuzione)'
} else {
    Write-Warning 'Docker non e'' installato o non e'' in esecuzione.'
    Write-Warning 'L''installazione prosegue, ma Gauntlet NON potra'' eseguire scansioni'
    Write-Warning 'finche'' Docker Desktop non sara'' installato e avviato'
    Write-Warning '(il daemon OWASP ZAP gira in un container).'
}

# --- Installazione del pacchetto -------------------------------------------
Write-Host '==> Installazione del pacchetto Gauntlet (CLI globale)'
if ($Installer -eq 'pipx') {
    # --force rende idempotente: reinstalla in modo pulito se gia'' presente.
    pipx install --force $RepoDir
    Write-Host '    installato con pipx'
} else {
    $Pip = if (Get-Command pip -ErrorAction SilentlyContinue) { 'pip' } else { 'pip3' }
    Write-Host "    pipx non trovato: fallback a '$Pip install --user'"
    # Nota: su ambienti recenti (PEP 668) pip puo' rifiutarsi con
    # 'externally-managed-environment'. In tal caso usa pipx (consigliato) oppure,
    # consapevolmente, 'pip install --user --break-system-packages'.
    & $Pip install --user $RepoDir
    Write-Host "    installato con $Pip --user"
}

# --- Registrazione della skill di Claude Code ------------------------------
Write-Host '==> Registrazione della skill di Claude Code'
New-Item -ItemType Directory -Force -Path $SkillsDir | Out-Null
Copy-Item -Force (Join-Path $RepoDir 'SKILL.md') (Join-Path $SkillsDir 'SKILL.md')
Write-Host "    SKILL.md copiato in $SkillsDir\SKILL.md"

# --- Verifica che il comando sia raggiungibile nel PATH --------------------
if (-not (Get-Command gauntlet -ErrorAction SilentlyContinue)) {
    Write-Warning "Il comando 'gauntlet' e' stato installato ma non e' nel PATH di questa sessione."
    Write-Warning "Per renderlo raggiungibile: esegui 'pipx ensurepath', poi chiudi e riapri il terminale."
    Write-Warning "Poi verifica con 'Get-Command gauntlet'."
}

Write-Host ''
Write-Host "Fatto. Il comando 'gauntlet' e' installato e la skill e' registrata in"
Write-Host "  $SkillsDir\"
Write-Host ''
Write-Host 'Promemoria:'
Write-Host '  - Docker Desktop deve essere in esecuzione: il daemon OWASP ZAP gira in un container.'
Write-Host "  - In ogni progetto serve un contratto 'gauntlet.yaml' (vedi gauntlet.example.yaml)"
Write-Host '    e le password degli account esportate come variabili d''ambiente.'
Write-Host ''
Write-Host "Se 'gauntlet' non viene trovato subito, assicurati che la cartella bin di"
Write-Host "pipx/pip sia nel PATH (es. 'pipx ensurepath', poi riapri il terminale)."
