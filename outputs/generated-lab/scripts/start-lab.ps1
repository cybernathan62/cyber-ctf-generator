param(
    [switch]$SkipVmDeploy,
    [switch]$SkipPfSenseRestore,
    [switch]$SkipDebianCutover,
    [switch]$SkipRuntimePing,
    [switch]$SkipBootstrapValidation
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

Write-Host "========================================"
Write-Host " ETAPE 1/5 - VM DEPLOY "
Write-Host "========================================"
if (-not $SkipVmDeploy) { vagrant up }

Write-Host "========================================"
Write-Host " ETAPE 2/5 - PFSENSE RESTORE "
Write-Host "========================================"
if (-not $SkipPfSenseRestore) { Write-Host "TODO: restore pfSense here" }

Write-Host "========================================"
Write-Host " ETAPE 3/5 - BOOTSTRAP VALIDATION "
Write-Host "========================================"
if (-not $SkipBootstrapValidation) { Write-Host "TODO: ansible bootstrap validation" }

Write-Host "========================================"
Write-Host " ETAPE 4/5 - DEBIAN CUTOVER + DMZ SITE "
Write-Host "========================================"
if (-not $SkipDebianCutover) { Write-Host "TODO: debian cutover + DMZ site" }

Write-Host "========================================"
Write-Host " ETAPE 5/5 - FINAL VALIDATION "
Write-Host "========================================"
if (-not $SkipRuntimePing) { Write-Host "TODO: runtime validation" }
