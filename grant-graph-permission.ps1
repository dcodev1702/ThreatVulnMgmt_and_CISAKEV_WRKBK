# Grant Microsoft Graph application permission ThreatHunting.Read.All to a
# user-assigned managed identity. Idempotent.
#
# Required Microsoft Entra role to run this script: at least one of
#   - Cloud Application Administrator
#   - Application Administrator
#   - Privileged Role Administrator
#
# Usage:
#   .\grant-graph-permission.ps1
#       [-UamiName mi-tvm-graph-ingest]
#       [-ResourceGroup Sentinel]
#       [-Subscription 192ad012-896e-4f14-8525-c37a2a9640f9]
#       [-AppRoleId dd98c7f5-2d42-42d3-a0e4-633161547251]   # ThreatHunting.Read.All

[CmdletBinding()]
param(
    [string]$UamiName       = 'mi-tvm-graph-ingest',
    [string]$ResourceGroup  = 'Sentinel',
    [string]$Subscription   = '192ad012-896e-4f14-8525-c37a2a9640f9',
    [string]$AppRoleId      = 'dd98c7f5-2d42-42d3-a0e4-633161547251'
)

$ErrorActionPreference = 'Stop'

Write-Host "Looking up UAMI principalId..."
$miPrincipalId = az identity show -g $ResourceGroup -n $UamiName --subscription $Subscription --query principalId -o tsv
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
