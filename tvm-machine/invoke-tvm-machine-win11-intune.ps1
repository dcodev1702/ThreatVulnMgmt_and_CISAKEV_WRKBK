[CmdletBinding()]
param(
    [string]$ResourceGroup = 'Sentinel',
    [string]$SubscriptionName = 'zolab',
    [string]$SubscriptionId = '',
    [string]$LogicAppName = 'la-tvm-win11-intune',
    [string]$TriggerName = 'DailyAt04UTC'
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

$uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Logic/workflows/$LogicAppName/triggers/$TriggerName/run?api-version=2019-05-01"

Write-Host "Triggering Logic App '$LogicAppName' trigger '$TriggerName'..."
$result = az rest --method POST --uri $uri
if ($LASTEXITCODE -ne 0) {
    throw "az rest trigger call failed."
}

$result