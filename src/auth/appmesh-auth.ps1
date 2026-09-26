#!/usr/bin/env powershell
################################################################################
## Native Windows launcher for the bundled authentication System App.
##
## The Linux/macOS package uses appmesh-auth.sh. The installed identity.yaml and
## dexuser.yaml are patched on Windows to invoke this script, while retaining the
## same actions and persisted work/auth layout.
################################################################################

param(
    [Parameter(Position = 0)]
    [ValidateSet("bootstrap", "service", "service-health", "dex", "dex-health", "admin-ui", "admin-ui-health", "automation-token", "user-token", "print-initial-password", "rotate-initial-password", "set-initial-password", "forget-initial-password", "add-user", "delete-user")]
    [string]$Action = "",
    [Parameter(Position = 1)]
    [string]$Username = "",
    [Parameter(Position = 2)]
    [string]$Role = ""
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
$DaemonConfig = Join-Path $AppMeshRoot "work\config\config.yaml"
if (-not (Test-Path -LiteralPath $DaemonConfig -PathType Leaf)) {
    $DaemonConfig = Join-Path $AppMeshRoot "config\config.yaml"
}
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
$PasshashHelper = Join-Path $AppMeshRoot "bin\passhash.exe"
$DexExecutable = Join-Path $AppMeshRoot "bin\dex.exe"
# Dex administration web UI binary (the fork's examples/example-app), run by
# the dexuser System App through the admin-ui action below.
$AdminUiExecutable = Join-Path $AppMeshRoot "bin\dexuser.exe"
# Mutual-TLS material for the Dex administrative gRPC listener. The launcher
# enables that listener only when the server certificate, its key, and the
# client authority all exist.
$AuthTlsDir = Join-Path $AppMeshRoot "ssl"
$GrpcTlsCert = Join-Path $AuthTlsDir "server.pem"
$GrpcTlsKey = Join-Path $AuthTlsDir "server-key.pem"
$GrpcTlsClientCA = Join-Path $AuthTlsDir "ca.pem"
$GrpcClientCert = Join-Path $AuthTlsDir "client.pem"
$GrpcClientKey = Join-Path $AuthTlsDir "client-key.pem"

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
            # [System.IO.File]::Replace with a $null backup throws "The path is
            # not of a legal form" under Windows PowerShell 5.1; Move-Item -Force
            # overwrites atomically on the same volume, like mv -f on POSIX.
            Move-Item -LiteralPath $temporary -Destination $Path -Force
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
        [string]$Path,
        [string]$Field,
        [string]$Fallback
    )
    $value = [Environment]::GetEnvironmentVariable($EnvironmentName)
    if ($value) { return $value }
    $value = Get-YamlScalar -Path $Path -Field $Field -Fallback ""
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
    Assert-PlainFile $PasshashHelper "passhash helper"
    # The helper trims one trailing '\n' then one '\r' (passhash/src/main.rs);
    # PowerShell's native pipe appends exactly one CRLF, so the manual "`n"
    # would leave a stray newline in the hashed password and break logins.
    $hash = ($Password | & $PasshashHelper) -join ""
    if ($LASTEXITCODE -ne 0 -or $hash -notmatch '^\$2[aby]\$10\$[./A-Za-z0-9]{53}$') {
        throw "passhash helper returned an invalid bcrypt hash"
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
    $issuer = Get-AuthEnvironmentOrYaml "APPMESH_AUTH_ISSUER" $OidcConfig "issuer" "http://127.0.0.1:6062/auth"
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

# Single web redirect URI: <origin of browser_entry> + /oauth/callback. An empty
# browser_entry derives the daemon's own HTTPS REST listener, the same default
# the daemon advertises in /appmesh/auth/config, so Dex and the advertised
# entry always agree on one address.
function Get-WebRedirectUri {
    $browserEntry = Get-AuthEnvironmentOrYaml "APPMESH_AUTH_BROWSER_ENTRY" $OidcConfig "browser_entry" ""
    if (-not $browserEntry) {
        $address = Get-EnvironmentOrYaml "APPMESH_REST_RestListenAddress" $DaemonConfig "RestListenAddress" "127.0.0.1"
        $port = Get-EnvironmentOrYaml "APPMESH_REST_RestListenPort" $DaemonConfig "RestListenPort" "6060"
        $browserEntry = "https://${address}:${port}"
    }
    $schemeSeparator = $browserEntry.IndexOf("://")
    if ($schemeSeparator -lt 1) {
        throw "browser_entry must be an absolute http(s) URL: $browserEntry"
    }
    $rest = $browserEntry.Substring($schemeSeparator + 3)
    $end = $rest.IndexOfAny([char[]]@("/", "?", "#"))
    if ($end -ge 0) { $rest = $rest.Substring(0, $end) }
    return $browserEntry.Substring(0, $schemeSeparator + 3) + $rest + "/oauth/callback"
}

function Render-DexConfig {
    Assert-PlainFile $DexConfigTemplate "authentication configuration template"
    $admin = Read-KeyValueFile $AdminCredentials
    $guest = Read-KeyValueFile $GuestCredentials
    $automation = Read-KeyValueFile $AutomationClientFile
    $issuer = Get-AuthEnvironmentOrYaml "APPMESH_AUTH_ISSUER" $OidcConfig "issuer" "http://127.0.0.1:6062/auth"
    $listen = Get-EnvironmentOrYaml "APPMESH_AUTH_LISTEN" $AuthStackConfig "listen" "127.0.0.1:6062"
    $telemetry = Get-EnvironmentOrYaml "APPMESH_AUTH_TELEMETRY_LISTEN" $AuthStackConfig "telemetry_listen" "127.0.0.1:6063"
    $webRedirectUri = Get-WebRedirectUri

    $content = [System.IO.File]::ReadAllText($DexConfigTemplate)
    # Windows runs the CGO-free dex build: memory storage, no SQLite database.
    # A template change leaves the marker unresolved and fails the check below.
    $content = $content -replace "(?m)^  type: sqlite3\r?\n  config:\r?\n    file: __APPMESH_AUTH_STORAGE_PATH__\r?$", "  type: memory"
    # Pure PKCE deployments drop the resource-owner password grant from the Dex
    # grant types; the Engine reads the same setting to advertise the flows.
    # The password database stays enabled, so browser sign-in keeps working.
    # Keep this in sync with the grantTypes rewrite in appmesh-auth.sh.
    $passwordFlow = Get-AuthEnvironmentOrYaml "APPMESH_AUTH_PASSWORD_FLOW" $OidcConfig "password_flow" "true"
    if ($passwordFlow -match '^(?i)(0|false|off|disabled)$') {
        $updated = $content -replace '(?m)^  grantTypes: \["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code", "password", "client_credentials"\]\r?$', '  grantTypes: ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code", "client_credentials"]'
        # A template drift must never silently keep a grant the operator disabled.
        if ($updated -eq $content) { throw "The authentication configuration template grantTypes line does not match; cannot drop the password grant" }
        $content = $updated
    }
    elseif ($passwordFlow -notmatch '^(?i)(1|true)$') {
        # Keep this accepted set identical to the Engine's (OidcTokenVerifier.cpp).
        throw "APPMESH_AUTH_PASSWORD_FLOW must be true or false"
    }
    # The administrative gRPC listener serves the dexuser administration UI and
    # is optional: it is rendered only when the mutual-TLS material is present,
    # because Dex refuses to start when a configured certificate file is missing
    # and the authentication service gates every sign-in. A template change
    # leaves a marker unresolved and fails the check below.
    $grpcEnabled = (Test-Path -LiteralPath $GrpcTlsCert -PathType Leaf) -and
        (Test-Path -LiteralPath $GrpcTlsKey -PathType Leaf) -and
        (Test-Path -LiteralPath $GrpcTlsClientCA -PathType Leaf)
    if ($grpcEnabled) {
        # Control markers, not configuration: never emit them, because the
        # final check rejects any unresolved marker text.
        $content = $content -replace "(?m)^# __APPMESH_AUTH_GRPC_BEGIN__\r?\n", ""
        $content = $content -replace "(?m)^# __APPMESH_AUTH_GRPC_END__\r?\n", ""
    } else {
        $content = $content -replace "(?ms)^# __APPMESH_AUTH_GRPC_BEGIN__\r?\n.*?^# __APPMESH_AUTH_GRPC_END__\r?\n", ""
    }
    $grpcListen = if ($env:APPMESH_AUTH_GRPC_LISTEN) { $env:APPMESH_AUTH_GRPC_LISTEN } else { "127.0.0.1:5557" }
    $replacements = [ordered]@{
        "__APPMESH_AUTH_ISSUER__" = $issuer
        "__APPMESH_AUTH_LISTEN__" = $listen
        "__APPMESH_AUTH_TELEMETRY_LISTEN__" = $telemetry
        "__APPMESH_AUTH_WEB_CALLBACK__" = $webRedirectUri
        "__APPMESH_AUTH_INITIAL_ADMIN_EMAIL__" = $AdminEmail
        "__APPMESH_AUTH_INITIAL_ADMIN_PASSWORD_HASH__" = $admin.password_hash
        "__APPMESH_AUTH_INITIAL_ADMIN_USERNAME__" = $AdminUsername
        "__APPMESH_AUTH_INITIAL_ADMIN_USER_ID__" = $AdminUserId
        "__APPMESH_AUTH_INITIAL_GUEST_EMAIL__" = $GuestEmail
        "__APPMESH_AUTH_INITIAL_GUEST_PASSWORD_HASH__" = $guest.password_hash
        "__APPMESH_AUTH_INITIAL_GUEST_USERNAME__" = $GuestUsername
        "__APPMESH_AUTH_INITIAL_GUEST_USER_ID__" = $GuestUserId
        "__APPMESH_AUTH_AUTOMATION_SECRET__" = $automation.secret
    }
    if ($grpcEnabled) {
        $replacements["__APPMESH_AUTH_GRPC_LISTEN__"] = $grpcListen
        $replacements["__APPMESH_AUTH_GRPC_TLS_CERT__"] = $GrpcTlsCert
        $replacements["__APPMESH_AUTH_GRPC_TLS_KEY__"] = $GrpcTlsKey
        $replacements["__APPMESH_AUTH_GRPC_TLS_CLIENT_CA__"] = $GrpcTlsClientCA
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
    $accessUrl = Get-AuthEnvironmentOrYaml "APPMESH_AUTH_ACCESS_URL" $OidcConfig "access_url" "http://127.0.0.1:6062/auth"
    $tlsVerify = Get-AuthEnvironmentOrYaml "APPMESH_AUTH_TLS_VERIFY" $OidcConfig "tls_verify" "true"
    $caPath = Get-AuthEnvironmentOrYaml "APPMESH_AUTH_CA_PATH" $OidcConfig "ca_path" ""
    $curlArguments = @("--fail", "--silent", "--show-error", "--connect-timeout", "2", "--max-time", "8", "--request", "POST")
    if ($tlsVerify -in @("false", "False", "FALSE", "0")) { $curlArguments += "--insecure" }
    if ($caPath) {
        if (Test-Path -LiteralPath $caPath -PathType Container) {
            $curlArguments += @("--capath", $caPath)
        } else {
            $curlArguments += @("--cacert", $caPath)
        }
    }
    $body = "grant_type=client_credentials&client_id=$AutomationClientId&client_secret=$($credential.secret)&scope=audience%3Aserver%3Aclient_id%3Aappmesh-api"
    # Pass the body as an argument: piping a string into a native command under
    # Windows PowerShell 5.1 appends CRLF, and the trailing newline in the last
    # form field makes dex reject the token request with 400.
    $curlArguments += @("--header", "Content-Type: application/x-www-form-urlencoded", "--data", $body, "--url", ($accessUrl.TrimEnd('/') + "/token"))
    $response = (& curl.exe @curlArguments) -join ""
    $body = $null
    if ($LASTEXITCODE -ne 0) { throw "The token request failed" }
    $token = ($response | ConvertFrom-Json).access_token
    $response = $null
    if (-not $token) { throw "The token response has no access_token" }
    [Console]::Out.Write($token)
}

function Request-UserToken {
    param([string]$User)
    Assert-BuiltinOwner
    if (-not $User) { $User = $AdminEmail }
    # The password comes from standard input, never from arguments or
    # environment; only the access token is printed.
    $password = [Console]::In.ReadLine()
    if ([string]::IsNullOrEmpty($password)) { throw "Provide the password on standard input" }
    if ($null -ne [Console]::In.ReadLine()) { throw "The password must be a single line" }
    $accessUrl = Get-AuthEnvironmentOrYaml "APPMESH_AUTH_ACCESS_URL" $OidcConfig "access_url" "http://127.0.0.1:6062/auth"
    $tlsVerify = Get-AuthEnvironmentOrYaml "APPMESH_AUTH_TLS_VERIFY" $OidcConfig "tls_verify" "true"
    $caPath = Get-AuthEnvironmentOrYaml "APPMESH_AUTH_CA_PATH" $OidcConfig "ca_path" ""
    $curlArguments = @("--fail", "--silent", "--show-error", "--connect-timeout", "2", "--max-time", "8", "--request", "POST")
    if ($tlsVerify -in @("false", "False", "FALSE", "0")) { $curlArguments += "--insecure" }
    if ($caPath) {
        if (Test-Path -LiteralPath $caPath -PathType Container) {
            $curlArguments += @("--capath", $caPath)
        } else {
            $curlArguments += @("--cacert", $caPath)
        }
    }
    $curlArguments += @(
        "--user", "appmesh-cli:",
        "--data-urlencode", "grant_type=password",
        "--data-urlencode", "username=$User",
        "--data-urlencode", "password=$password",
        "--data-urlencode", "scope=openid audience:server:client_id:appmesh-api",
        "--url", ($accessUrl.TrimEnd('/') + "/token")
    )
    $response = (& curl.exe @curlArguments) -join ""
    $password = $null
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

function Set-InitialPassword {
    Assert-BuiltinOwner
    # Read from standard input (never arguments or environment, which leak into
    # process listings and CI logs), the same rule as the shell port.
    $password = [Console]::In.ReadLine()
    if ([string]::IsNullOrEmpty($password)) {
        throw "Provide the initial administrator password on standard input"
    }
    if ($null -ne [Console]::In.ReadLine()) {
        throw "The initial administrator password must be a single line"
    }
    # bcrypt rejects inputs past 72 bytes; fail early with a clear message.
    if ([System.Text.Encoding]::UTF8.GetByteCount($password) -gt 72) {
        throw "The initial administrator password must be at most 72 bytes"
    }
    Ensure-PrivateDirectory $AuthSecretDir
    try {
        Write-InitialCredential $AdminCredentials $AdminEmail $AdminUsername $AdminUserId $password $true
        if (-not (Test-Path -LiteralPath $AdminMarker)) { Write-PrivateText $AdminMarker "initialized`n" }
    } finally {
        $password = $null
    }
    [Console]::Error.WriteLine("The initial administrator password was updated. Restart App Mesh to apply it.")
}

function Forget-InitialPassword {
    Assert-BuiltinOwner
    Assert-InitialCredential $AdminCredentials $AdminEmail $AdminUsername $AdminUserId "administrator"
    $credential = Read-KeyValueFile $AdminCredentials
    $content = "username=$AdminUsername`nemail=$AdminEmail`nuser_id=$AdminUserId`npassword_hash=$($credential.password_hash)`n"
    Write-PrivateText $AdminCredentials $content
    [Console]::Error.WriteLine("Removed the initial administrator plaintext password. The existing password hash remains configured.")
}

# Serve the Dex administration web UI (bin\dexuser.exe, built from the fork's
# examples/example-app). It talks to the Dex administrative gRPC API over
# mutual TLS, so it requires the same TLS material that gates the gRPC listener
# in Render-DexConfig. The UI has no authentication of its own and therefore
# listens on loopback only.
# The container entrypoint and the service environment file disable the UI with
# APPMESH_AUTH_ADMIN_UI=off; the dexuser App then stays up but serves nothing,
# like the identity App in external mode.
function Test-AdminUiDisabled {
    $flag = if ($env:APPMESH_AUTH_ADMIN_UI) { $env:APPMESH_AUTH_ADMIN_UI.ToLowerInvariant() } else { "on" }
    return $flag -in @("off", "false", "0", "disabled")
}

function Start-AdminUi {
    Assert-PlainFile $AdminUiExecutable "administration UI executable"
    foreach ($file in @($GrpcTlsCert, $GrpcTlsKey, $GrpcTlsClientCA, $GrpcClientCert, $GrpcClientKey)) {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
            throw "The administration UI is unavailable because the TLS material is incomplete in $AuthTlsDir"
        }
    }
    $listen = if ($env:APPMESH_AUTH_ADMIN_LISTEN) { $env:APPMESH_AUTH_ADMIN_LISTEN } else { "127.0.0.1:6064" }
    $issuer = Get-AuthEnvironmentOrYaml "APPMESH_AUTH_ISSUER" $OidcConfig "issuer" "http://127.0.0.1:6062/auth"
    $grpcListen = if ($env:APPMESH_AUTH_GRPC_LISTEN) { $env:APPMESH_AUTH_GRPC_LISTEN } else { "127.0.0.1:5557" }
    & $AdminUiExecutable --listen "http://$listen" --issuer $issuer --grpc-addr $grpcListen --grpc-ca $GrpcTlsClientCA --grpc-client-cert $GrpcClientCert --grpc-client-key $GrpcClientKey
    exit $LASTEXITCODE
}

function Test-AdminUiHealth {
    $listen = if ($env:APPMESH_AUTH_ADMIN_LISTEN) { $env:APPMESH_AUTH_ADMIN_LISTEN } else { "127.0.0.1:6064" }
    & curl.exe --fail --silent --show-error --max-time 2 "http://$listen/" | Out-Null
    exit $LASTEXITCODE
}

# The authorization policy a write must target: the runtime copy when it
# exists, the packaged template otherwise.
function Get-AuthorizationPolicySource {
    if (Test-Path -LiteralPath $AuthorizationRuntime) {
        Assert-PlainFile $AuthorizationRuntime "authorization runtime policy"
        return $AuthorizationRuntime
    }
    Assert-PlainFile $AuthorizationTemplate "authorization template"
    return $AuthorizationTemplate
}

# An undefined role makes the Engine reject the whole policy, so every caller
# checks before it writes. Principal keys share the four-space indent of role
# names, so the match is scoped to the roles section.
function Test-PolicyDefinesRole {
    param([string]$RoleName)
    $source = Get-AuthorizationPolicySource
    $inRoles = $false
    foreach ($line in [System.IO.File]::ReadAllLines($source)) {
        if ($line -eq "  roles:") { $inRoles = $true; continue }
        if ($line -match '^  [^ ]') { $inRoles = $false }
        if ($inRoles -and $line -eq "    ${RoleName}:") { return $true }
    }
    return $false
}

# Bind one Principal to one role in the authorization policy. The Engine owns
# this file and rewrites it on every administrative change, so a binding that
# is written while the Engine runs can be lost.
function Add-PrincipalBinding {
    param([string]$PrincipalId, [string]$Issuer, [string]$Subject, [string]$RoleName)
    $source = Get-AuthorizationPolicySource
    if (-not (Test-PolicyDefinesRole $RoleName)) {
        throw "The authorization policy does not define the role $RoleName"
    }
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.AddRange([System.IO.File]::ReadAllLines($source))
    if (($lines -join "`n") -match ('(?m)^\s{4}' + [regex]::Escape($PrincipalId) + ':\s*$')) {
        [Console]::Error.WriteLine("The authorization policy already lists $PrincipalId")
        return
    }
    $index = $lines.IndexOf("  principals:")
    if ($index -lt 0) { throw "authorization policy has no principals section" }
    $issuerYaml = ConvertTo-YamlSingleQuotedScalar $Issuer
    $block = [string[]]@(
        "    ${PrincipalId}:", "      kind: user", "      issuer: $issuerYaml",
        "      subject: $Subject", "      status: active", "      execution_user: `"`"",
        "      roles: [$RoleName]", ""
    )
    $lines.InsertRange($index + 1, $block)
    Write-PrivateText $AuthorizationRuntime (($lines -join "`n") + "`n")
}

# Remove one Principal from the authorization policy. It reports success when
# the policy does not list the Principal, because the caller only needs the
# entry to be absent. A Principal is its own line plus the six-space fields
# below it; the next four-space key ends the block.
function Remove-PrincipalBinding {
    param([string]$PrincipalId)
    $source = Get-AuthorizationPolicySource
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.AddRange([System.IO.File]::ReadAllLines($source))
    if (($lines -join "`n") -notmatch ('(?m)^\s{4}' + [regex]::Escape($PrincipalId) + ':\s*$')) {
        [Console]::Error.WriteLine("The authorization policy does not list $PrincipalId")
        return
    }
    $out = [System.Collections.Generic.List[string]]::new()
    $removing = $false
    foreach ($line in $lines) {
        if ($line -eq "    ${PrincipalId}:") { $removing = $true; continue }
        if ($removing -and $line -match '^      ') { continue }
        if ($removing) { $removing = $false }
        $out.Add($line)
    }
    Write-PrivateText $AuthorizationRuntime (($out -join "`n") + "`n")
}

# OIDC subject for a local password user: base64url_raw of the IDTokenSubject
# protobuf (field 1 user_id, field 2 connector id "local"), mirroring Dex's
# GenSubject.
function Get-OidcSubjectForUserId {
    param([string]$UserId)
    $userBytes = [System.Text.Encoding]::UTF8.GetBytes($UserId)
    $connBytes = [System.Text.Encoding]::UTF8.GetBytes("local")
    $bytes = [byte[]]@(0x0A, $userBytes.Length) + $userBytes + [byte[]]@(0x12, $connBytes.Length) + $connBytes
    return [Convert]::ToBase64String($bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')
}

# POST one form to the administration UI (the dexuser System App, loopback
# only). The UI answers every administrative write with a redirect: ?notice=
# on success and ?error= on failure, so the Location header carries the result.
# $PasswordFile carries the password field through a private file so the value
# never appears in a process argument list.
function Invoke-AdminUiPost {
    param([string]$Path, [string]$Body, [string]$PasswordFile = "")
    $listen = if ($env:APPMESH_AUTH_ADMIN_LISTEN) { $env:APPMESH_AUTH_ADMIN_LISTEN } else { "127.0.0.1:6064" }
    $curlArguments = @("--silent", "--show-error", "--max-time", "10", "--request", "POST",
        "--output", "NUL", "--dump-header", "-", "--data-raw", $Body)
    if ($PasswordFile) { $curlArguments += @("--data-urlencode", "password@$PasswordFile") }
    $headers = & curl.exe @curlArguments "http://$listen$Path"
    if ($LASTEXITCODE -ne 0) {
        throw "The administration UI is not reachable at http://${listen}; the dexuser System App must be running (see APPMESH_AUTH_ADMIN_UI)"
    }
    $location = ""
    foreach ($line in ($headers -split "`r?`n")) {
        if ($line -match '^[Ll]ocation:\s*(.+?)\s*$') { $location = $Matches[1] }
    }
    if ($location -match '[?&]error=([^&]*)') {
        $detail = [System.Net.WebUtility]::UrlDecode($Matches[1])
        throw "The administration UI rejected the request: $detail"
    }
}

function Add-User {
    param([string]$Email, [string]$RoleName)
    Assert-BuiltinOwner
    if (-not $Email) { throw "usage: appmesh-auth.ps1 add-user <email> [role]" }
    if (-not $RoleName) { $RoleName = "appmesh-viewer" }
    # Dex compares static emails case-insensitively, so this guard does too.
    if ($Email.ToLowerInvariant() -in @($AdminEmail, $GuestEmail)) {
        # Dex serves these from its static list, which is read-only through the
        # administrative API.
        throw "The $Email identity is a static entry in the authentication configuration. Dex cannot change it through the administrative API."
    }
    # A malformed address would create a stray identity, because Dex keys
    # password users by email. Reject it before creation.
    if ($Email -notmatch '.+@.+') { throw "The user address must be an email address: $Email" }
    # Check the role before the user is created. A half-done operation would
    # leave an identity in Dex that no policy authorizes.
    if (-not (Test-PolicyDefinesRole $RoleName)) {
        throw "The authorization policy does not define the role $RoleName"
    }

    # The password comes from standard input, never from arguments or
    # environment; the same rule as set-initial-password.
    $password = [Console]::In.ReadLine()
    if ([string]::IsNullOrEmpty($password)) { throw "Provide the user password on standard input" }
    if ($null -ne [Console]::In.ReadLine()) { throw "The user password must be a single line" }
    # bcrypt rejects inputs past 72 bytes; fail early with a clear message.
    if ([System.Text.Encoding]::UTF8.GetByteCount($password) -gt 72) {
        throw "The user password must be at most 72 bytes"
    }

    Ensure-PrivateDirectory $AuthSecretDir
    $hex = New-SecureHex 16
    $userId = $hex.Substring(0, 8) + "-" + $hex.Substring(8, 4) + "-" + $hex.Substring(12, 4) + "-" + $hex.Substring(16, 4) + "-" + $hex.Substring(20, 12)
    $username = $Email.Split('@')[0]

    # The UI hashes the password itself; hand it over through a private file so
    # it never appears in a process argument list.
    $passwordFile = Join-Path $AuthSecretDir (".add-user-" + [Guid]::NewGuid().ToString("N"))
    try {
        Write-PrivateText -Path $passwordFile -Content $password
        $password = $null
        $body = "email=" + [System.Net.WebUtility]::UrlEncode($Email) +
            "&username=" + [System.Net.WebUtility]::UrlEncode($username) +
            "&user_id=" + [System.Net.WebUtility]::UrlEncode($userId)
        Invoke-AdminUiPost "/admin/password/create" $body $passwordFile
    } finally {
        $password = $null
        if (Test-Path -LiteralPath $passwordFile) { Remove-Item -LiteralPath $passwordFile -Force }
    }

    $issuer = Get-AuthEnvironmentOrYaml "APPMESH_AUTH_ISSUER" $OidcConfig "issuer" "http://127.0.0.1:6062/auth"
    $subject = Get-OidcSubjectForUserId $userId
    $principalId = Get-StablePrincipalId $issuer $subject
    Add-PrincipalBinding $principalId $issuer $subject $RoleName

    [Console]::Error.WriteLine("Created the Dex password user $Email")
    [Console]::Error.WriteLine("  user_id:      $userId")
    [Console]::Error.WriteLine("  OIDC subject: $subject")
    [Console]::Error.WriteLine("  Principal ID: $principalId")
    [Console]::Error.WriteLine("  role:         $RoleName")

    [Console]::Error.WriteLine("Note: the authentication service on Windows uses memory storage; this user does not survive a restart. For durable user management, use an external identity provider.")
    $engineRunning = $null -ne (Get-Process -Name "appmesh" -ErrorAction SilentlyContinue)
    if ($engineRunning) {
        [Console]::Error.WriteLine("Note: a running Engine adopts this binding on the user's first request. If the user already authenticated before, the Engine holds a role-less record; apply the role through the REST API instead:")
        [Console]::Error.WriteLine("  POST /appmesh/principal/${principalId}  {`"roles`": [`"$RoleName`"]}")
    }
    [Console]::Out.WriteLine($principalId)
}

function Remove-User {
    param([string]$Email)
    Assert-BuiltinOwner
    if (-not $Email) { throw "usage: appmesh-auth.ps1 delete-user <email>" }
    if ($Email.ToLowerInvariant() -in @($AdminEmail, $GuestEmail)) {
        throw "The $Email identity is a static entry in the authentication configuration. Dex cannot delete it through the administrative API."
    }

    # The Principal binding keys on the OIDC subject, which embeds the user_id.
    # Recover it from the UI password list before the entry disappears; the
    # column layout mirrors the fork's admin.html passwords table.
    $listen = if ($env:APPMESH_AUTH_ADMIN_LISTEN) { $env:APPMESH_AUTH_ADMIN_LISTEN } else { "127.0.0.1:6064" }
    $page = (& curl.exe --fail --silent --show-error --max-time 10 "http://$listen/admin?section=passwords") -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "The administration UI is not reachable at http://${listen}; the dexuser System App must be running (see APPMESH_AUTH_ADMIN_UI)"
    }
    $userId = ""
    $rowPattern = [regex]('(?s)<td class="mono">' + [regex]::Escape($Email) + '</td>\s*<td[^>]*>[^<]*</td>\s*<td class="mono small">([^<]+)</td>')
    $rowMatch = $rowPattern.Match($page)
    if ($rowMatch.Success) { $userId = $rowMatch.Groups[1].Value }

    $principalId = ""
    if ($userId) {
        $issuer = Get-AuthEnvironmentOrYaml "APPMESH_AUTH_ISSUER" $OidcConfig "issuer" "http://127.0.0.1:6062/auth"
        $principalId = Get-StablePrincipalId $issuer (Get-OidcSubjectForUserId $userId)
    }

    Invoke-AdminUiPost "/admin/password/delete" ("email=" + [System.Net.WebUtility]::UrlEncode($Email))

    if ($principalId) { Remove-PrincipalBinding $principalId }

    [Console]::Error.WriteLine("Removed the Dex password user $Email")
    if ($userId) { [Console]::Error.WriteLine("  user_id:      $userId") }
    if ($principalId) {
        [Console]::Error.WriteLine("  Principal ID: $principalId")
    } else {
        [Console]::Error.WriteLine("  The user identifier is unknown, so no Principal record was removed.")
    }

    $engineRunning = $null -ne (Get-Process -Name "appmesh" -ErrorAction SilentlyContinue)
    if ($principalId -and $engineRunning) {
        [Console]::Error.WriteLine("Warning: the Engine owns the authorization policy and rewrites it from memory. Remove the Principal through the REST API when the Engine is running:")
        [Console]::Error.WriteLine("  DELETE /appmesh/principal/${principalId}")
    }
    if ($principalId) { [Console]::Out.WriteLine($principalId) }
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
            $listen = Get-EnvironmentOrYaml "APPMESH_AUTH_TELEMETRY_LISTEN" $AuthStackConfig "telemetry_listen" "127.0.0.1:6063"
            & curl.exe --fail --silent --show-error --max-time 2 "http://$listen/healthz" | Out-Null
            exit $LASTEXITCODE
        }
        "admin-ui" {
            if ((Get-AuthMode) -ne "builtin" -or -not (Test-AuthOwner) -or (Test-AdminUiDisabled)) {
                while ($true) { Start-Sleep -Seconds 3600 }
            }
            Start-AdminUi
        }
        "admin-ui-health" {
            if ((Get-AuthMode) -ne "builtin" -or -not (Test-AuthOwner) -or (Test-AdminUiDisabled)) { exit 0 }
            Test-AdminUiHealth
        }
        "automation-token" { Request-AutomationToken }
        "user-token" { Request-UserToken $Username }
        "print-initial-password" { Print-InitialPassword }
        "rotate-initial-password" { Rotate-InitialPassword }
        "set-initial-password" { Set-InitialPassword }
        "forget-initial-password" { Forget-InitialPassword }
        "add-user" { Add-User $Username $Role }
        "delete-user" { Remove-User $Username }
        default { throw "usage: appmesh-auth.ps1 {bootstrap|service|service-health|admin-ui|admin-ui-health|automation-token|user-token|print-initial-password|rotate-initial-password|set-initial-password|forget-initial-password|add-user|delete-user} [username] [role]" }
    }
} catch {
    Fail $_.Exception.Message
}
