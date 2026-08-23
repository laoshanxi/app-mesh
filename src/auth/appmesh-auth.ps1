#!/usr/bin/env powershell
################################################################################
## Native Windows launcher for the bundled authentication System App.
##
## The Linux/macOS package uses appmesh-auth.sh. The installed auth-service.yaml is
## patched on Windows to invoke this script, while retaining the same actions and
## persisted work/auth layout.
################################################################################

param(
    [Parameter(Position = 0)]
    [ValidateSet("bootstrap", "service", "service-health", "dex", "dex-health", "automation-token", "print-initial-password", "rotate-initial-password", "forget-initial-password")]
    [string]$Action = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$AppMeshRoot = if ($env:APPMESH_HOME) {
    [System.IO.Path]::GetFullPath($env:APPMESH_HOME)
} else {
    [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
}
$AuthStateDir = Join-Path $AppMeshRoot "work\auth"
$AuthSecretDir = Join-Path $AuthStateDir "secrets"
$AuthStackConfig = Join-Path $AppMeshRoot "work\config\auth-stack.yaml"
$OidcConfig = Join-Path $AppMeshRoot "work\config\oidc.yaml"
$DexConfigTemplate = Join-Path $AppMeshRoot "config\dex.yaml"
$DexRuntimeDir = Join-Path $AuthStateDir "dex"
$DexRuntimeConfig = Join-Path $DexRuntimeDir "dex.yaml"
$AdminCredentials = Join-Path $AuthSecretDir "initial-admin-credentials"
$LegacyAdminCredentials = Join-Path $AuthSecretDir "dex-initial-admin-credentials"
$AdminMarker = Join-Path $AuthSecretDir "dex-initial-admin-initialized"
$GuestCredentials = Join-Path $AuthSecretDir "initial-viewer-credentials"
$LegacyGuestCredentials = Join-Path $AuthSecretDir "dex-initial-guest-credentials"
$GuestMarker = Join-Path $AuthSecretDir "dex-initial-guest-initialized"
$AutomationClientFile = Join-Path $AuthSecretDir "automation-client"
$AuthorizationTemplate = Join-Path $AppMeshRoot "config\authorization.yaml"
$AuthorizationRuntime = Join-Path $AppMeshRoot "work\config\authorization.yaml"
$PasswordHashHelper = Join-Path $AppMeshRoot "bin\password-hash.exe"
$DexExecutable = Join-Path $AppMeshRoot "bin\dex.exe"

$AdminEmail = "admin@appmesh.local"
$AdminUsername = "admin"
$AdminUserId = "2d1c8c38-3898-4c89-a78b-3caa42f203c1"
$GuestEmail = "guest@appmesh.local"
$GuestUsername = "guest"
$GuestUserId = "93ad39b4-eb6f-4945-97a1-3366451867fb"
$GuestSubject = "CiQ5M2FkMzliNC1lYjZmLTQ5NDUtOTdhMS0zMzY2NDUxODY3ZmISBWxvY2Fs"
$AutomationClientId = "appmesh-automation"
$AutomationSubject = "ChJhcHBtZXNoLWF1dG9tYXRpb24"
$AutomationRole = "appmesh-maintenance"

function Fail {
    param([string]$Message)
    [Console]::Error.WriteLine($Message)
    exit 1
}

function Assert-PlainFile {
    param([string]$Path, [string]$Description)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Description does not exist: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Description must not be a reparse point: $Path"
    }
}

function Protect-PrivatePath {
    param([string]$Path, [switch]$Directory)
    $grant = if ($Directory) { "(OI)(CI)F" } else { "F" }
    & icacls.exe $Path /inheritance:r /grant:r "*S-1-5-18:$grant" "*S-1-5-32-544:$grant" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "failed to protect authentication state path: $Path"
    }
}

function Ensure-PrivateDirectory {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "authentication state directory must be a plain directory: $Path"
        }
    } else {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    Protect-PrivatePath -Path $Path -Directory
}

function Write-PrivateText {
    param([string]$Path, [string]$Content)
    $directory = Split-Path -Parent $Path
    Ensure-PrivateDirectory $directory
    $temporary = Join-Path $directory ("." + [System.IO.Path]::GetFileName($Path) + "." + [Guid]::NewGuid().ToString("N"))
    try {
        [System.IO.File]::WriteAllText($temporary, $Content, (New-Object System.Text.UTF8Encoding($false)))
        Protect-PrivatePath $temporary
        if (Test-Path -LiteralPath $Path) {
            Assert-PlainFile $Path "authentication state file"
            [System.IO.File]::Replace($temporary, $Path, $null)
        } else {
            [System.IO.File]::Move($temporary, $Path)
        }
        Protect-PrivatePath $Path
    } finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function Read-KeyValueFile {
    param([string]$Path)
    Assert-PlainFile $Path "credential file"
    $result = @{}
    foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
        $separator = $line.IndexOf('=')
        if ($separator -gt 0) {
            $result[$line.Substring(0, $separator)] = $line.Substring($separator + 1)
        }
    }
    return $result
}

function Get-YamlScalar {
    param([string]$Path, [string]$Field, [string]$Fallback)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $Fallback
    }
    foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
        if ($line -match ('^\s*' + [regex]::Escape($Field) + '\s*:\s*(.*?)\s*$')) {
            $value = $Matches[1].Trim()
            if (($value.StartsWith('"') -and $value.EndsWith('"')) -or
                ($value.StartsWith("'") -and $value.EndsWith("'"))) {
                $value = $value.Substring(1, $value.Length - 2)
            }
            if ($value) { return $value }
        }
    }
    return $Fallback
}

function Get-EnvironmentOrYaml {
    param([string]$EnvironmentName, [string]$Path, [string]$Field, [string]$Fallback)
    $value = [Environment]::GetEnvironmentVariable($EnvironmentName)
    if ($value) { return $value }
    return Get-YamlScalar -Path $Path -Field $Field -Fallback $Fallback
}

function Get-AuthEnvironmentOrYaml {
    param(
        [string]$EnvironmentName,
        [string]$LegacyEnvironmentName,
        [string]$Path,
        [string]$Field,
        [string]$Fallback,
        [string]$LegacyField = ""
    )
    $value = [Environment]::GetEnvironmentVariable($EnvironmentName)
    if (-not $value) { $value = [Environment]::GetEnvironmentVariable($LegacyEnvironmentName) }
    if ($value) { return $value }
    $value = Get-YamlScalar -Path $Path -Field $Field -Fallback ""
    if (-not $value -and $LegacyField) {
        $value = Get-YamlScalar -Path $Path -Field $LegacyField -Fallback ""
    }
    if ($value) { return $value }
    return $Fallback
}

function New-SecureHex {
    param([int]$ByteCount)
    $bytes = New-Object byte[] $ByteCount
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
        return ([BitConverter]::ToString($bytes)).Replace("-", "").ToLowerInvariant()
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
        $generator.Dispose()
    }
}

function Get-PasswordHash {
    param([string]$Password)
    Assert-PlainFile $PasswordHashHelper "password-hash helper"
    $hash = (($Password + "`n") | & $PasswordHashHelper) -join ""
    if ($LASTEXITCODE -ne 0 -or $hash -notmatch '^\$2[aby]\$10\$[./A-Za-z0-9]{53}$') {
        throw "password-hash helper returned an invalid bcrypt hash"
    }
    return $hash
}

function Write-InitialCredential {
    param(
        [string]$Path,
        [string]$Email,
        [string]$Username,
        [string]$UserId,
        [string]$Password,
        [bool]$IncludePassword
    )
    $hash = Get-PasswordHash $Password
    $lines = @(
        "username=$Username",
        "email=$Email",
        "user_id=$UserId",
        "password_hash=$hash"
    )
    if ($IncludePassword) { $lines += "password=$Password" }
    Write-PrivateText -Path $Path -Content (($lines -join "`n") + "`n")
    $hash = $null
}

function Assert-InitialCredential {
    param([string]$Path, [string]$Email, [string]$Username, [string]$UserId, [string]$Label)
    $credential = Read-KeyValueFile $Path
    if ($credential.email -ne $Email -or $credential.username -ne $Username -or $credential.user_id -ne $UserId -or
        $credential.password_hash -notmatch '^\$2[aby]\$10\$[./A-Za-z0-9]{53}$') {
        throw "The initial $Label credential is invalid"
    }
}

function Ensure-InitialCredential {
    param([string]$Path, [string]$Marker, [string]$Email, [string]$Username, [string]$UserId, [string]$Label)
    if (Test-Path -LiteralPath $Path) {
        Assert-InitialCredential $Path $Email $Username $UserId $Label
        if (-not (Test-Path -LiteralPath $Marker)) { Write-PrivateText $Marker "initialized`n" }
        return
    }
    if (Test-Path -LiteralPath $Marker) {
        throw "The initial $Label credential was removed. rotate-initial-password can create an administrator replacement."
    }
    $password = New-SecureHex 24
    try {
        Write-InitialCredential $Path $Email $Username $UserId $password $true
        Write-PrivateText $Marker "initialized`n"
    } finally {
        $password = $null
    }
}

function Ensure-AutomationClient {
    if (Test-Path -LiteralPath $AutomationClientFile) {
        $credential = Read-KeyValueFile $AutomationClientFile
        if ($credential.client_id -ne $AutomationClientId -or $credential.secret -notmatch '^[0-9a-f]{64}$') {
            throw "automation client credential is invalid"
        }
        return
    }
    $secret = New-SecureHex 32
    try {
        Write-PrivateText $AutomationClientFile "client_id=$AutomationClientId`nsecret=$secret`n"
    } finally {
        $secret = $null
    }
}

function Get-StablePrincipalId {
    param([string]$Issuer, [string]$Subject)
    $issuerBytes = [System.Text.Encoding]::UTF8.GetBytes($Issuer)
    $subjectBytes = [System.Text.Encoding]::UTF8.GetBytes($Subject)
    $material = New-Object byte[] ($issuerBytes.Length + 1 + $subjectBytes.Length)
    [Array]::Copy($issuerBytes, 0, $material, 0, $issuerBytes.Length)
    [Array]::Copy($subjectBytes, 0, $material, $issuerBytes.Length + 1, $subjectBytes.Length)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return "oidc:" + ([BitConverter]::ToString($sha.ComputeHash($material))).Replace("-", "").ToLowerInvariant()
    } finally {
        [Array]::Clear($material, 0, $material.Length)
        $sha.Dispose()
    }
}

function ConvertTo-YamlSingleQuotedScalar {
    param([string]$Value)
    if ($Value.Contains("`r") -or $Value.Contains("`n")) {
        throw "Authentication configuration values must not contain newlines"
    }
    return "'" + $Value.Replace("'", "''") + "'"
}

function Seed-BuiltinPrincipals {
    Assert-PlainFile $AuthorizationTemplate "authorization template"
    $issuer = Get-AuthEnvironmentOrYaml "APPMESH_AUTH_ISSUER" "APPMESH_DEX_ISSUER" $OidcConfig "issuer" "http://127.0.0.1:6062/auth"
    $automationId = Get-StablePrincipalId $issuer $AutomationSubject
    $guestId = Get-StablePrincipalId $issuer $GuestSubject
    $source = if (Test-Path -LiteralPath $AuthorizationRuntime) { $AuthorizationRuntime } else { $AuthorizationTemplate }
    Assert-PlainFile $source "authorization policy"
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.AddRange([System.IO.File]::ReadAllLines($source))
    $text = $lines -join "`n"
    $issuerYaml = ConvertTo-YamlSingleQuotedScalar $issuer

    if ($text -notmatch ('(?m)^\s{4}' + [regex]::Escape($automationId) + ':\s*$')) {
        $index = $lines.IndexOf("  principals:")
        if ($index -lt 0) { throw "authorization policy has no principals section" }
        $block = [string[]]@(
            "    ${automationId}:", "      kind: service", "      issuer: $issuerYaml",
            "      subject: $AutomationSubject", "      status: active", "      execution_user: `"`"",
            "      roles: [$AutomationRole]", ""
        )
        $lines.InsertRange($index + 1, $block)
    }
    $text = $lines -join "`n"
    if ($text -notmatch ('(?m)^\s{4}' + [regex]::Escape($guestId) + ':\s*$')) {
        $index = $lines.IndexOf("  principals:")
        $block = [string[]]@(
            "    ${guestId}:", "      kind: user", "      issuer: $issuerYaml",
            "      subject: $GuestSubject", "      status: active", "      execution_user: `"`"",
            "      roles: [appmesh-viewer]", ""
        )
        $lines.InsertRange($index + 1, $block)
    }
    Write-PrivateText $AuthorizationRuntime (($lines -join "`n") + "`n")
}

function Initialize-AuthState {
    Ensure-PrivateDirectory $AuthStateDir
    Ensure-PrivateDirectory $AuthSecretDir
    Ensure-PrivateDirectory $DexRuntimeDir
    if ((Test-Path -LiteralPath $LegacyAdminCredentials -PathType Leaf) -and -not (Test-Path -LiteralPath $AdminCredentials)) {
        Assert-PlainFile $LegacyAdminCredentials "legacy administrator credential"
        Move-Item -LiteralPath $LegacyAdminCredentials -Destination $AdminCredentials
    }
    if ((Test-Path -LiteralPath $LegacyGuestCredentials -PathType Leaf) -and -not (Test-Path -LiteralPath $GuestCredentials)) {
        Assert-PlainFile $LegacyGuestCredentials "legacy viewer credential"
        Move-Item -LiteralPath $LegacyGuestCredentials -Destination $GuestCredentials
    }
    Ensure-InitialCredential $AdminCredentials $AdminMarker $AdminEmail $AdminUsername $AdminUserId "administrator"
    Ensure-InitialCredential $GuestCredentials $GuestMarker $GuestEmail $GuestUsername $GuestUserId "guest"
    Ensure-AutomationClient
    Seed-BuiltinPrincipals
    $ready = Join-Path $AuthStateDir "bootstrap.ready"
    if (-not (Test-Path -LiteralPath $ready)) { Write-PrivateText $ready "ready`n" }
}

function Render-DexConfig {
    Assert-PlainFile $DexConfigTemplate "authentication configuration template"
    $admin = Read-KeyValueFile $AdminCredentials
    $guest = Read-KeyValueFile $GuestCredentials
    $automation = Read-KeyValueFile $AutomationClientFile
    $issuer = Get-AuthEnvironmentOrYaml "APPMESH_AUTH_ISSUER" "APPMESH_DEX_ISSUER" $OidcConfig "issuer" "http://127.0.0.1:6062/auth"
    $listen = Get-EnvironmentOrYaml "APPMESH_AUTH_DEX_LISTEN" $AuthStackConfig "dex_listen" "127.0.0.1:6062"
    $telemetry = Get-EnvironmentOrYaml "APPMESH_AUTH_DEX_TELEMETRY_LISTEN" $AuthStackConfig "dex_telemetry_listen" "127.0.0.1:6063"
    $callback = Get-YamlScalar $AuthStackConfig "web_callback" "https://127.0.0.1:6060/oauth/callback"

    $content = [System.IO.File]::ReadAllText($DexConfigTemplate)
    $replacements = [ordered]@{
        "__APPMESH_DEX_ISSUER__" = $issuer
        "__APPMESH_DEX_STORAGE_PATH__" = (Join-Path $DexRuntimeDir "dex.db")
        "__APPMESH_DEX_LISTEN__" = $listen
        "__APPMESH_DEX_TELEMETRY_LISTEN__" = $telemetry
        "__APPMESH_DEX_WEB_CALLBACK__" = $callback
        "__APPMESH_DEX_INITIAL_ADMIN_EMAIL__" = $AdminEmail
        "__APPMESH_DEX_INITIAL_ADMIN_PASSWORD_HASH__" = $admin.password_hash
        "__APPMESH_DEX_INITIAL_ADMIN_USERNAME__" = $AdminUsername
        "__APPMESH_DEX_INITIAL_ADMIN_USER_ID__" = $AdminUserId
        "__APPMESH_DEX_INITIAL_GUEST_EMAIL__" = $GuestEmail
        "__APPMESH_DEX_INITIAL_GUEST_PASSWORD_HASH__" = $guest.password_hash
        "__APPMESH_DEX_INITIAL_GUEST_USERNAME__" = $GuestUsername
        "__APPMESH_DEX_INITIAL_GUEST_USER_ID__" = $GuestUserId
        "__APPMESH_DEX_AUTOMATION_SECRET__" = $automation.secret
    }
    foreach ($marker in $replacements.Keys) {
        $content = $content.Replace($marker, (ConvertTo-YamlSingleQuotedScalar ([string]$replacements[$marker])))
    }
    if ($content.Contains("__APPMESH_")) { throw "The authentication configuration template contains an unresolved marker" }
    Write-PrivateText $DexRuntimeConfig $content
}

function Get-AuthMode {
    if ($env:APPMESH_AUTH_MODE) { return $env:APPMESH_AUTH_MODE }
    return "builtin"
}

function Get-AuthRole {
    return Get-EnvironmentOrYaml "APPMESH_AUTH_ROLE" $AuthStackConfig "role" "standalone"
}

function Test-AuthOwner {
    $role = Get-AuthRole
    if ($role -notin @("standalone", "owner", "follower")) { throw "invalid AuthStack.role" }
    return $role -in @("standalone", "owner")
}

function Assert-BuiltinOwner {
    if ((Get-AuthMode) -ne "builtin" -or -not (Test-AuthOwner)) {
        throw "the requested action is available only from the built-in auth owner"
    }
}

function Request-AutomationToken {
    Assert-BuiltinOwner
    $credential = Read-KeyValueFile $AutomationClientFile
    $accessUrl = Get-AuthEnvironmentOrYaml "APPMESH_AUTH_ACCESS_URL" "APPMESH_DEX_ACCESS_URL" $OidcConfig "access_url" "http://127.0.0.1:6062/auth" "dex_access_url"
    $tlsVerify = Get-AuthEnvironmentOrYaml "APPMESH_AUTH_TLS_VERIFY" "APPMESH_DEX_TLS_VERIFY" $OidcConfig "tls_verify" "true" "dex_tls_verify"
    $caPath = Get-AuthEnvironmentOrYaml "APPMESH_AUTH_CA_PATH" "APPMESH_DEX_CA_PATH" $OidcConfig "ca_path" "" "dex_ca_path"
    $curlArguments = @("--fail", "--silent", "--show-error", "--connect-timeout", "2", "--max-time", "8", "--request", "POST")
    if ($tlsVerify -in @("false", "False", "FALSE", "0")) { $curlArguments += "--insecure" }
    if ($caPath) {
        if (Test-Path -LiteralPath $caPath -PathType Container) {
            $curlArguments += @("--capath", $caPath)
        } else {
            $curlArguments += @("--cacert", $caPath)
        }
    }
    $curlArguments += @("--header", "Content-Type: application/x-www-form-urlencoded", "--data-binary", "@-", "--url", ($accessUrl.TrimEnd('/') + "/token"))
    $body = "grant_type=client_credentials&client_id=$AutomationClientId&client_secret=$($credential.secret)&scope=audience%3Aserver%3Aclient_id%3Aappmesh-api"
    $response = ($body | & curl.exe @curlArguments) -join ""
    $body = $null
    if ($LASTEXITCODE -ne 0) { throw "The token request failed" }
    $token = ($response | ConvertFrom-Json).access_token
    $response = $null
    if (-not $token) { throw "The token response has no access_token" }
    [Console]::Out.Write($token)
}

function Print-InitialPassword {
    Assert-BuiltinOwner
    Assert-InitialCredential $AdminCredentials $AdminEmail $AdminUsername $AdminUserId "administrator"
    $credential = Read-KeyValueFile $AdminCredentials
    if (-not $credential.password) {
        throw "The initial administrator password is not recoverable. rotate-initial-password can create a new one."
    }
    [Console]::Out.WriteLine($credential.password)
}

function Rotate-InitialPassword {
    Assert-BuiltinOwner
    Ensure-PrivateDirectory $AuthSecretDir
    $password = New-SecureHex 24
    try {
        Write-InitialCredential $AdminCredentials $AdminEmail $AdminUsername $AdminUserId $password $true
        if (-not (Test-Path -LiteralPath $AdminMarker)) { Write-PrivateText $AdminMarker "initialized`n" }
    } finally {
        $password = $null
    }
    [Console]::Error.WriteLine("The initial administrator password was rotated. Run print-initial-password to read it, then restart App Mesh.")
}

function Forget-InitialPassword {
    Assert-BuiltinOwner
    Assert-InitialCredential $AdminCredentials $AdminEmail $AdminUsername $AdminUserId "administrator"
    $credential = Read-KeyValueFile $AdminCredentials
    $content = "username=$AdminUsername`nemail=$AdminEmail`nuser_id=$AdminUserId`npassword_hash=$($credential.password_hash)`n"
    Write-PrivateText $AdminCredentials $content
    [Console]::Error.WriteLine("Removed the initial administrator plaintext password. The existing password hash remains configured.")
}

try {
    switch ($Action) {
        "bootstrap" {
            if ((Get-AuthMode) -eq "builtin" -and (Test-AuthOwner)) {
                Initialize-AuthState
                Render-DexConfig
                [Console]::Error.WriteLine("App Mesh authentication state initialized")
            }
        }
        { $_ -in @("service", "dex") } {
            if ((Get-AuthMode) -ne "builtin" -or -not (Test-AuthOwner)) {
                while ($true) { Start-Sleep -Seconds 3600 }
            }
            Initialize-AuthState
            Render-DexConfig
            Assert-PlainFile $DexExecutable "authentication service executable"
            $env:DEX_CLIENT_CREDENTIAL_GRANT_ENABLED_BY_DEFAULT = "true"
            & $DexExecutable serve $DexRuntimeConfig
            exit $LASTEXITCODE
        }
        { $_ -in @("service-health", "dex-health") } {
            if ((Get-AuthMode) -ne "builtin" -or -not (Test-AuthOwner)) { exit 0 }
            $listen = Get-EnvironmentOrYaml "APPMESH_AUTH_DEX_TELEMETRY_LISTEN" $AuthStackConfig "dex_telemetry_listen" "127.0.0.1:6063"
            & curl.exe --fail --silent --show-error --max-time 2 "http://$listen/healthz" | Out-Null
            exit $LASTEXITCODE
        }
        "automation-token" { Request-AutomationToken }
        "print-initial-password" { Print-InitialPassword }
        "rotate-initial-password" { Rotate-InitialPassword }
        "forget-initial-password" { Forget-InitialPassword }
        default { throw "usage: appmesh-auth.ps1 {bootstrap|service|service-health|automation-token|print-initial-password|rotate-initial-password|forget-initial-password}" }
    }
} catch {
    Fail $_.Exception.Message
}
