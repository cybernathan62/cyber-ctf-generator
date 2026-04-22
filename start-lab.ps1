$ErrorActionPreference = "Stop"

$projectRoot   = Split-Path -Parent $PSScriptRoot
$restoreScript = Join-Path $PSScriptRoot "restore-pfsense.ps1"
$debianScript  = Join-Path $PSScriptRoot "configure-debian.ps1"

Set-Location $projectRoot

$debianVMs = @(
    "bastion",
    "dmz",
    "wazuh",
    "zabbix",
    "db-server"
)

$pfsenseVMs = @(
    "pfsense-1",
    "pfsense-2",
    "pfsense-3"
)

$ansibleImage = "ctf-ansible:latest"

function Invoke-Step {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Action
    )

    Write-Host ""
    Write-Host "===================================" -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host "===================================" -ForegroundColor Cyan

    & $Action
}

function Wait-SecondsInfo {
    param(
        [int]$Seconds = 15,
        [string]$Message = "Attente"
    )

    Write-Host "[INFO] $Message ($Seconds sec)..." -ForegroundColor Yellow
    Start-Sleep -Seconds $Seconds
}

function Test-CommandExists {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CommandName
    )

    if (-not (Get-Command $CommandName -ErrorAction SilentlyContinue)) {
        throw "Commande introuvable : $CommandName"
    }
}

function Start-DockerDesktopIfNeeded {
    param(
        [int]$TimeoutSeconds = 180
    )

    Write-Host "[INFO] Vérification de Docker..." -ForegroundColor Cyan

    try {
        docker info *> $null
        Write-Host "[OK] Docker est déjà prêt." -ForegroundColor Green
        return
    }
    catch {
        Write-Host "[WARN] Docker ne répond pas. Tentative de démarrage..." -ForegroundColor Yellow
    }

    try {
        Write-Host "[INFO] Arrêt propre WSL..." -ForegroundColor Cyan
        wsl --shutdown *> $null
    }
    catch {
        Write-Host "[WARN] Impossible d'arrêter WSL proprement, on continue..." -ForegroundColor Yellow
    }

    $dockerDesktopPaths = @(
        "$Env:ProgramFiles\Docker\Docker\Docker Desktop.exe",
        "$Env:LocalAppData\Programs\Docker\Docker\Docker Desktop.exe",
        "$Env:LocalAppData\Docker\Docker Desktop.exe"
    )

    $dockerStarted = $false

    foreach ($path in $dockerDesktopPaths) {
        if (Test-Path $path) {
            Write-Host "[INFO] Lancement de Docker Desktop : $path" -ForegroundColor Cyan
            Start-Process -FilePath $path
            $dockerStarted = $true
            break
        }
    }

    if (-not $dockerStarted) {
        throw "Docker Desktop.exe introuvable. Vérifie l'installation de Docker Desktop."
    }

    $start = Get-Date
    do {
        Start-Sleep -Seconds 5
        try {
            docker info *> $null
            Write-Host "[OK] Docker est prêt." -ForegroundColor Green
            return
        }
        catch {
            Write-Host "[INFO] En attente du moteur Docker..." -ForegroundColor Yellow
        }
    } while (((Get-Date) - $start).TotalSeconds -lt $TimeoutSeconds)

    throw "Docker Desktop a été lancé, mais le moteur Docker n'est pas prêt après $TimeoutSeconds secondes."
}

function Test-DockerImage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ImageName
    )

    docker image inspect $ImageName *> $null
}

function Invoke-ExternalCommandChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [string[]]$Arguments = @(),

        [Parameter(Mandatory = $true)]
        [string]$ErrorMessage
    )

    & $FilePath @Arguments

    if ($LASTEXITCODE -ne 0) {
        throw "$ErrorMessage (code=$LASTEXITCODE)"
    }
}

function Invoke-AnsibleInDocker {
    param(
        [Parameter(Mandatory = $true)]
        [string]$StepName,

        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    Write-Host ""
    Write-Host "[INFO] $StepName" -ForegroundColor Cyan

    $mountPath = $projectRoot -replace '\\', '/'

    docker run --rm `
        -v "${mountPath}:/work" `
        -w /work/ansible `
        $ansibleImage /bin/sh -c $Command

    if ($LASTEXITCODE -ne 0) {
        throw "Echec étape Docker/Ansible : $StepName (code=$LASTEXITCODE)"
    }
}

function Start-VagrantVMs {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$VMNames
    )

    foreach ($vm in $VMNames) {
        Write-Host "[INFO] Démarrage VM : $vm" -ForegroundColor Cyan
        vagrant up $vm

        if ($LASTEXITCODE -ne 0) {
            throw "Echec démarrage VM : $vm (code=$LASTEXITCODE)"
        }
    }
}

try {
    Invoke-Step -Title "ETAPE 0/5 - PRECHECK OUTILS" -Action {
        Test-CommandExists -CommandName "docker"
        Test-CommandExists -CommandName "vagrant"

        if (-not (Test-Path $restoreScript)) {
            throw "Script introuvable : $restoreScript"
        }

        if (-not (Test-Path $debianScript)) {
            throw "Script introuvable : $debianScript"
        }

        if (-not (Test-Path (Join-Path $projectRoot "ansible\inventories\lab\hosts-runtime.yml"))) {
            throw "Inventory introuvable : ansible\inventories\lab\hosts-runtime.yml"
        }

        if (-not (Test-Path (Join-Path $projectRoot "ansible\playbooks\wazuh-all-in-one.yml"))) {
            throw "Playbook introuvable : ansible\playbooks\wazuh-all-in-one.yml"
        }

        Write-Host "[OK] Precheck outils/fichiers validé." -ForegroundColor Green
    }

    Invoke-Step -Title "ETAPE 1/5 - VERIFICATION DOCKER + IMAGE ANSIBLE" -Action {
        Start-DockerDesktopIfNeeded
        Test-DockerImage -ImageName $ansibleImage
        Write-Host "[OK] Image Docker Ansible trouvée : $ansibleImage" -ForegroundColor Green
    }

    Invoke-Step -Title "ETAPE 2/5 - DEMARRAGE DES VM PFSENSE" -Action {
        Start-VagrantVMs -VMNames $pfsenseVMs
        Wait-SecondsInfo -Seconds 20 -Message "Attente initialisation pfSense"
    }

    Invoke-Step -Title "ETAPE 3/5 - RESTAURATION CONFIG PFSENSE" -Action {
        try {
            & $restoreScript
        }
        catch {
            throw "Echec restauration pfSense : $($_.Exception.Message)"
        }

        if (-not $?) {
            throw "Echec restauration pfSense : le script restore-pfsense.ps1 a signalé un échec."
        }

        Write-Host "[OK] Restauration pfSense terminée." -ForegroundColor Green
        Wait-SecondsInfo -Seconds 15 -Message "Attente après restauration pfSense"
    }

    Invoke-Step -Title "ETAPE 4/5 - DEMARRAGE + CONFIGURATION DES DEBIAN" -Action {
        Start-VagrantVMs -VMNames $debianVMs
        Wait-SecondsInfo -Seconds 20 -Message "Attente initialisation Debian"

        try {
            & $debianScript
        }
        catch {
            throw "Echec configuration Debian : $($_.Exception.Message)"
        }

        if (-not $?) {
            throw "Echec configuration Debian : le script configure-debian.ps1 a signalé un échec."
        }

        Write-Host "[OK] Configuration Debian terminée." -ForegroundColor Green
        Wait-SecondsInfo -Seconds 15 -Message "Attente stabilisation Debian"
    }

    Invoke-Step -Title "ETAPE 5/5 - INSTALLATION WAZUH ALL-IN-ONE" -Action {
        Invoke-AnsibleInDocker `
            -StepName "Ping host wazuh" `
            -Command "echo '=== TEST PING WAZUH ===' && ansible wazuh -i inventories/lab/hosts-runtime.yml -m ping"

        Invoke-AnsibleInDocker `
            -StepName "Execution playbook wazuh all-in-one" `
            -Command "echo '=== EXECUTION PLAYBOOK WAZUH ALL-IN-ONE ===' && ansible-playbook -i inventories/lab/hosts-runtime.yml playbooks/wazuh-all-in-one.yml -l wazuh -v"
    }

    Write-Host ""
    Write-Host "[OK] Lab démarré complètement." -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Host "[ERREUR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "[AIDE] Vérifie l'étape indiquée ci-dessus. Docker est OK, donc regarde surtout restore-pfsense.ps1 / configure-debian.ps1 / Ansible selon l'étape." -ForegroundColor Yellow
    exit 1
}