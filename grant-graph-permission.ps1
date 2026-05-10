# Grant Microsoft Graph application permission ThreatHunting.Read.All to a
# user-assigned managed identity. Idempotent.
#
# Required Microsoft Entra role to run this script: at least one of
#   - Cloud Application Administrator
#   - Application Administrator
#   - Privileged Role Administrator
#
# Subscription discovery: this script resolves the subscription GUID at runtime
# from a subscription *name* (default 'Security') using the Az PowerShell cmdlet
# Get-AzSubscription. Falls back to `az account list` if the Az module is not
# installed. Pass -SubscriptionId explicitly to skip discovery entirely.
#
# Usage:
#   .\grant-graph-permission.ps1
#       [-UamiName mi-tvm-graph-ingest]
#       [-ResourceGroup Sentinel]
#       [-SubscriptionName 'Security']
#       [-SubscriptionId '<guid>']                          # optional override
#       [-AppRoleId dd98c7f5-2d42-42d3-a0e4-633161547251]   # ThreatHunting.Read.All

[CmdletBinding()]
param(
    [string]$UamiName         = 'mi-tvm-graph-ingest',
    [string]$ResourceGroup    = 'Sentinel',
    [string]$SubscriptionName = 'Security',
    [string]$SubscriptionId   = '',
    [string]$AppRoleId        = 'dd98c7f5-2d42-42d3-a0e4-633161547251'
)

$ErrorActionPreference = 'Stop'

# --- Resolve SubscriptionId from SubscriptionName -----------------------------
# Prefer the Az PowerShell cmdlet. If the Az module isn't loaded/installed,
# fall back to `az account list` so the script still works on minimal hosts.
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

Write-Host "Looking up Microsoft Graph service principal..."
$graphSpId = az ad sp list --filter "appId eq '00000003-0000-0000-c000-000000000000'" --query "[0].id" -o tsv
if ([string]::IsNullOrWhiteSpace($graphSpId)) {
    throw "Could not find Microsoft Graph service principal in this tenant."
}
Write-Host "Microsoft Graph SP id: $graphSpId"

# Wait briefly for the UAMI service principal to propagate to Microsoft Graph
# after creation (Azure RM creates UAMI faster than Graph indexes it).
$miSpFound = $false
for ($i = 0; $i -lt 12 -and -not $miSpFound; $i++) {
    try {
        $resp = az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$miPrincipalId" --query id -o tsv 2>$null
        if (-not [string]::IsNullOrWhiteSpace($resp)) { $miSpFound = $true; break }
    } catch { }
    Write-Host "Waiting for UAMI SP $miPrincipalId to be visible in Graph... ($i)"
    Start-Sleep -Seconds 5
}
if (-not $miSpFound) {
    Write-Warning "UAMI SP not visible in Graph yet. Continuing anyway; will retry the assignment."
}

Write-Host "Checking existing app role assignments..."
$existing = az rest --method GET `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$miPrincipalId/appRoleAssignments" `
    --query "value[?appRoleId=='$AppRoleId' && resourceId=='$graphSpId']" -o json 2>$null
if ($existing -and $existing -ne '[]') {
    Write-Host "Already granted. Nothing to do."
    Write-Host $existing
    exit 0
}

Write-Host "Granting Microsoft Graph appRoleId=$AppRoleId to UAMI principalId=$miPrincipalId..."
$body = @{
    principalId = $miPrincipalId
    resourceId  = $graphSpId
    appRoleId   = $AppRoleId
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
