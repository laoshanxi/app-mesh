#!/usr/bin/env powershell
################################################################################
## Post-install configuration for App Mesh on Windows.
##
## Windows packages are external-issuer-only: no bundled Dex, no auth System
## Apps, and first-administrator enrollment is compiled out. This script is the
## setup.sh counterpart for exactly that external-issuer surface: it validates
## the issuer/routing/TLS values and persists them into the operator override
## `work\config\oidc.yaml`, which the daemon prefers over the packaged
## `config\oidc.yaml`. It accepts no user or client password and provisions no
## roles. Delete `work\config\oidc.yaml` to return to the packaged defaults.
################################################################################

param(
    # Canonical external Dex issuer, identical across the deployment.
    [Parameter(Mandatory = $true)]
    [string]$Issuer,

    # Per-node discovery/JWKS route; defaults to the issuer.
    [string]$AccessUrl = "",

    # Verify the external route certificate: true or false (default: true).
    [string]$TlsVerify = "true",

    # Optional CA file or directory for the external route. Omit to keep the
    # value already stored in the override file.
    [string]$CaPath = "",

    # Remove a previously configured CA path.
    [switch]$ClearCa,

    # Do not restart the AppMeshService service after writing the override.
    [switch]$NoRestart
)

$ErrorActionPreference = "Stop"

function Write-Fatal {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Red
    exit 1
}

function Test-OidcUrl {
    param([string]$Name, [string]$Value)
    if ($Value -notmatch '^(https?)://(\[[0-9A-Fa-f:.]+\]|[^/:?\#\s@]+)(:[0-9]+)?(/[^?\#\s]*)?$') {
        Write-Fatal "$Name must be an absolute HTTP(S) URL without credentials, query, fragment, or whitespace: $Value"
    }
}

# Input validation happens before any file is modified.
Test-OidcUrl "-Issuer" $Issuer
if (-not $AccessUrl) { $AccessUrl = $Issuer }
Test-OidcUrl "-AccessUrl" $AccessUrl

switch ($TlsVerify.ToLowerInvariant()) {
    "true" { $TlsVerify = "true" }
    "1" { $TlsVerify = "true" }
    "false" { $TlsVerify = "false" }
    "0" { $TlsVerify = "false" }
    default { Write-Fatal "-TlsVerify must be true or false" }
}

if ($ClearCa -and $CaPath) {
    Write-Fatal "Use either -CaPath or -ClearCa, not both"
}
if ($CaPath) {
    if (-not [System.IO.Path]::IsPathRooted($CaPath)) {
        Write-Fatal "-CaPath must be an absolute path: $CaPath"
    }
    if (-not (Test-Path $CaPath)) {
        Write-Fatal "-CaPath does not exist: $CaPath"
    }
}

# The script ships as <install>\script\setup.ps1.
$AppMeshHome = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$PackagedOidc = Join-Path $AppMeshHome "config\oidc.yaml"
$OverrideDir = Join-Path $AppMeshHome "work\config"
$OverrideOidc = Join-Path $OverrideDir "oidc.yaml"
$NssmExe = Join-Path $AppMeshHome "bin\nssm.exe"

if (-not (Test-Path $PackagedOidc)) {
    Write-Fatal "Packaged OIDC configuration not found: $PackagedOidc"
}

# Seed the operator override from the packaged default once, then patch fields.
# Field lines are rewritten in place so the YAML structure stays untouched.
if (-not (Test-Path $OverrideOidc)) {
    New-Item -ItemType Directory -Force -Path $OverrideDir | Out-Null
    Copy-Item $PackagedOidc $OverrideOidc
    Write-Host "Created OIDC override: $OverrideOidc"
}

function Update-OidcField {
    param([string]$Path, [string]$Field, [string]$Value)
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.AddRange([System.IO.File]::ReadAllLines($Path))
    $pattern = '^(\s*)' + [regex]::Escape($Field) + '\s*:.*$'
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match $pattern) {
            # Preserve the original indentation; quote an empty scalar.
            $rendered = if ($Value -eq "") { '""' } else { $Value }
            $lines[$i] = "{0}{1}: {2}" -f $Matches[1], $Field, $rendered
            [System.IO.File]::WriteAllLines($Path, $lines, [System.Text.UTF8Encoding]::new($false))
            return
        }
    }
    Write-Fatal "field '$Field' not found in $Path; delete the file to restore the packaged default"
}

Update-OidcField -Path $OverrideOidc -Field "issuer" -Value $Issuer
Update-OidcField -Path $OverrideOidc -Field "dex_access_url" -Value $AccessUrl
Update-OidcField -Path $OverrideOidc -Field "dex_tls_verify" -Value $TlsVerify
if ($ClearCa) {
    Update-OidcField -Path $OverrideOidc -Field "dex_ca_path" -Value ""
}
elseif ($CaPath) {
    Update-OidcField -Path $OverrideOidc -Field "dex_ca_path" -Value $CaPath
}
Write-Host "Configured external Dex issuer <${Issuer}> (access: ${AccessUrl}, TLS verify: ${TlsVerify})" -ForegroundColor Green

# Restart the service so the running Engine picks up the override.
$service = Get-Service -Name "AppMeshService" -ErrorAction SilentlyContinue
if (-not $service) {
    Write-Warning "AppMeshService is not installed; start the daemon manually to apply the new issuer."
    exit 0
}
if (-not $NoRestart) {
    if (-not (Test-Path $NssmExe)) {
        Write-Fatal "nssm.exe not found to restart AppMeshService: $NssmExe"
    }
    & $NssmExe restart AppMeshService | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Fatal "failed to restart AppMeshService (exit code $LASTEXITCODE); the override is written but the running daemon still uses the previous issuer"
    }
    Write-Host "AppMeshService restarted." -ForegroundColor Green
}
Write-Host "Next: provision the first administrator by hand (Install.md, 'First login'), then run: appm logon" -ForegroundColor Cyan
exit 0
