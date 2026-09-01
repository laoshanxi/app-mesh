#!/usr/bin/env powershell
################################################################################
## Post-install configuration for App Mesh on Windows.
##
## Windows packages use the bundled authentication service by default. This script switches an installed
## service to an operator-managed external issuer by persisting the issuer/routing/
## TLS override and setting APPMESH_AUTH_MODE=external on the NSSM service. It
## accepts no user or client password and provisions no roles.
################################################################################

param(
    # Canonical external issuer, identical across the deployment.
    [Parameter(Mandatory = $true)]
    [string]$Issuer,

    # Per-node discovery/JWKS route; defaults to the issuer.
    [string]$AccessUrl = "",

    # Browser entry that fronts the issuer path; defaults to the issuer.
    [string]$BrowserEntry = "",

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

function ConvertTo-YamlDoubleQuotedScalar {
    param([string]$Value)
    $escaped = $Value.Replace('\', '\\').Replace('"', '\"')
    return '"' + $escaped + '"'
}

# Input validation happens before any file is modified.
Test-OidcUrl "-Issuer" $Issuer
if (-not $AccessUrl) { $AccessUrl = $Issuer }
Test-OidcUrl "-AccessUrl" $AccessUrl
if (-not $BrowserEntry) { $BrowserEntry = $Issuer }
Test-OidcUrl "-BrowserEntry" $BrowserEntry

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
$AuthServiceDefinition = Join-Path $AppMeshHome "apps\identity.yaml"
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

function Set-AuthServiceStatus {
    param([int]$Status)
    if (-not (Test-Path -LiteralPath $AuthServiceDefinition -PathType Leaf)) {
        Write-Fatal "Bundled authentication App definition not found: $AuthServiceDefinition"
    }
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.AddRange([System.IO.File]::ReadAllLines($AuthServiceDefinition))
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^status\s*:') {
            $lines[$i] = "status: $Status"
            [System.IO.File]::WriteAllLines($AuthServiceDefinition, $lines, [System.Text.UTF8Encoding]::new($false))
            return
        }
    }
    Write-Fatal "Bundled authentication App definition has no status field: $AuthServiceDefinition"
}

Update-OidcField -Path $OverrideOidc -Field "issuer" -Value $Issuer
Update-OidcField -Path $OverrideOidc -Field "access_url" -Value $AccessUrl
Update-OidcField -Path $OverrideOidc -Field "browser_entry" -Value $BrowserEntry
Update-OidcField -Path $OverrideOidc -Field "tls_verify" -Value $TlsVerify
if ($ClearCa) {
    Update-OidcField -Path $OverrideOidc -Field "ca_path" -Value ""
}
elseif ($CaPath) {
    Update-OidcField -Path $OverrideOidc -Field "ca_path" -Value (ConvertTo-YamlDoubleQuotedScalar $CaPath)
}
Write-Host "Configured external authentication issuer <${Issuer}> (access: ${AccessUrl}, entry: ${BrowserEntry}, TLS verify: ${TlsVerify})" -ForegroundColor Green

# The node must reach the advertised browser entry. The check uses the
# configured TLS posture. curl.exe ships with Windows 10 1803 and later.
$curlExe = Get-Command curl.exe -ErrorAction SilentlyContinue
if (-not $curlExe) {
    Write-Warning "curl.exe is not available; skipped the authentication entry reachability check: $BrowserEntry"
}
else {
    $curlArgs = @("-fsS", "--connect-timeout", "5", "--max-time", "15", "--output", "NUL", $BrowserEntry)
    if ($TlsVerify -eq "false") { $curlArgs += "--insecure" }
    if ($CaPath) {
        if (Test-Path -LiteralPath $CaPath -PathType Container) { $curlArgs += @("--capath", $CaPath) }
        else { $curlArgs += @("--cacert", $CaPath) }
    }
    & $curlExe.Source @curlArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Fatal "The authentication entry is not reachable: $BrowserEntry. Check the address and the network, then run setup again."
    }
}
Set-AuthServiceStatus 0
Write-Host "Authentication mode set to external. The bundled authentication service is disabled." -ForegroundColor Green

# Restart the service so the running Engine picks up the override.
$service = Get-Service -Name "AppMeshService" -ErrorAction SilentlyContinue
if (-not $service) {
    Write-Warning "AppMeshService is not installed; start the daemon manually to apply the new issuer."
    exit 0
}
if (-not (Test-Path $NssmExe)) {
    Write-Fatal "nssm.exe not found to configure AppMeshService: $NssmExe"
}
# nssm replaces the whole AppEnvironmentExtra list, so merge instead of overwrite.
$serviceEnvironment = @(& $NssmExe get AppMeshService AppEnvironmentExtra)
if ($LASTEXITCODE -ne 0) {
    Write-Fatal "failed to read the AppMeshService environment"
}
$updatedEnvironment = [System.Collections.Generic.List[string]]::new()
foreach ($entry in $serviceEnvironment) {
    if ($entry -and $entry -notmatch '^APPMESH_AUTH_MODE=') {
        $updatedEnvironment.Add([string]$entry)
    }
}
$updatedEnvironment.Add("APPMESH_AUTH_MODE=external")
& $NssmExe set AppMeshService AppEnvironmentExtra @updatedEnvironment | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Fatal "failed to set external authentication mode on AppMeshService"
}
if (-not $NoRestart) {
    & $NssmExe restart AppMeshService | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Fatal "failed to restart AppMeshService (exit code $LASTEXITCODE); the override is written but the running daemon still uses the previous issuer"
    }
    Write-Host "AppMeshService restarted." -ForegroundColor Green
}
Write-Host "External issuer configured. Provision its Principal bindings, then run: appm logon" -ForegroundColor Cyan
exit 0
