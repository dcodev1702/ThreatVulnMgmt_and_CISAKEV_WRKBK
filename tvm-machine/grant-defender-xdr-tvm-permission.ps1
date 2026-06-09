# Grant Microsoft Defender XDR application permission Vulnerability.Read.All to
# the shared user-assigned managed identity. Idempotent.
#
# Required Microsoft Entra role to run this script: at least one of
#   - Cloud Application Administrator
#   - Application Administrator
#   - Privileged Role Administrator
#
# Usage:
#   .\grant-defender-xdr-tvm-permission.ps1
#       [-UamiName mi-tvm-graph-ingest]
#       [-ResourceGroup Sentinel]
#       [-SubscriptionName 'Security']
#       [-SubscriptionId '<guid>']

[CmdletBinding()]
param(
    [string]$UamiName = 'mi-tvm-graph-ingest',
    [string]$ResourceGroup = 'Sentinel',
    [string]$SubscriptionName = 'Security',
    [string]$SubscriptionId = '',
    [string]$DefenderResourceAppId = 'fc780465-2017-40d4-a0c5-307022471b92',
    [string]$DefenderResourceDisplayName = 'WindowsDefenderATP',
    [string]$AppRoleValue = 'Vulnerability.Read.All'
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
    Write-Host "Resolving subscription '$SubscriptionName' to a subscription id..."

    $resolved = $null
    if (Get-Command Get-AzSubscription -ErrorAction SilentlyContinue) {
        try {
            $sub = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction Stop
            $resolved = $sub.Id
        } catch {
            Write-Warning "Get-AzSubscription failed ($($_.Exception.Message)). Falling back to az CLI."
        }
    } else {
        Write-Warning "Az PowerShell module not found. Falling back to 'az account list'. Install with: Install-Module Az -Scope CurrentUser"
    }

    if ([string]::IsNullOrWhiteSpace($resolved)) {
        $resolved = az account list --query "[?name=='$SubscriptionName'] | [0].id" -o tsv 2>$null
    }

    if ([string]::IsNullOrWhiteSpace($resolved)) {
        throw "Could not resolve subscription named '$SubscriptionName'. Connect with Connect-AzAccount or 'az login', or pass -SubscriptionId explicitly."
    }

    $SubscriptionId = $resolved
    Write-Host "Resolved '$SubscriptionName' -> $SubscriptionId"
}

Write-Host "Looking up UAMI principalId..."
$miPrincipalId = az identity show -g $ResourceGroup -n $UamiName --subscription $SubscriptionId --query principalId -o tsv
if ([string]::IsNullOrWhiteSpace($miPrincipalId)) {
    throw "UAMI '$UamiName' not found in resource group '$ResourceGroup'."
}
Write-Host "UAMI principalId: $miPrincipalId"

Write-Host "Looking up Defender XDR service principal..."
$defenderSpJson = $null
try {
    $defenderSpJson = az ad sp show --id $DefenderResourceAppId -o json 2>$null
} catch { }

if ([string]::IsNullOrWhiteSpace($defenderSpJson)) {
    $defenderSpJson = az ad sp list --display-name $DefenderResourceDisplayName --query '[0]' -o json 2>$null
}

if ([string]::IsNullOrWhiteSpace($defenderSpJson) -or $defenderSpJson -eq 'null') {
    throw "Could not find the Defender XDR service principal. Tried appId '$DefenderResourceAppId' and display name '$DefenderResourceDisplayName'."
}

$defenderSp = $defenderSpJson | ConvertFrom-Json
$defenderSpId = $defenderSp.id
Write-Host "Defender XDR SP id: $defenderSpId"

$appRole = $defenderSp.appRoles |
    Where-Object { $_.value -eq $AppRoleValue -and $_.isEnabled -eq $true -and $_.allowedMemberTypes -contains 'Application' } |
    Select-Object -First 1

if (-not $appRole) {
    throw "Could not find enabled application app role '$AppRoleValue' on Defender XDR service principal '$defenderSpId'."
}

$appRoleId = $appRole.id
Write-Host "Defender XDR app role '$AppRoleValue': $appRoleId"

try {
    $resp = az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$miPrincipalId" --query id -o tsv 2>$null
    if ([string]::IsNullOrWhiteSpace($resp)) {
        Write-Warning "UAMI SP not visible in Graph yet. Continuing anyway; the assignment call will report if propagation is still pending."
    }
} catch {
    Write-Warning "Could not verify UAMI SP visibility in Graph. Continuing anyway; the assignment call will report if propagation is still pending."
}

Write-Host "Checking existing app role assignments..."
$existing = az rest --method GET `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$miPrincipalId/appRoleAssignments" `
    --query "value[?appRoleId=='$appRoleId' && resourceId=='$defenderSpId']" -o json 2>$null
if ($existing -and $existing -ne '[]') {
    Write-Host "Already granted. Nothing to do."
    Write-Host $existing
    exit 0
}

Write-Host "Granting Defender XDR '$AppRoleValue' to UAMI principalId=$miPrincipalId..."
$body = @{
    principalId = $miPrincipalId
    resourceId  = $defenderSpId
    appRoleId   = $appRoleId
} | ConvertTo-Json -Compress

$tmp = [System.IO.Path]::GetTempFileName()
try {
    Set-Content -Path $tmp -Value $body -Encoding utf8
    $result = az rest --method POST `
        --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$miPrincipalId/appRoleAssignments" `
        --headers 'Content-Type=application/json' `
        --body "@$tmp"
    if ($LASTEXITCODE -ne 0) {
        throw "az rest failed: $result"
    }
    Write-Host "Granted."
    Write-Host $result
} finally {
    Remove-Item $tmp -ErrorAction SilentlyContinue
}