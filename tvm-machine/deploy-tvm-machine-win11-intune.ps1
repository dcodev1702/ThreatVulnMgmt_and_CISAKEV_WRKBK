[CmdletBinding()]
param(
    [string]$ResourceGroup = 'Sentinel',
    [string]$SubscriptionName = 'zolab',
    [string]$SubscriptionId = '',
    [string]$WorkspaceSubscriptionName = 'Security',
    [string]$WorkspaceSubscriptionId = '',
    [string]$WorkspaceResourceGroup = 'Sentinel',
    [string]$WorkspaceName = 'DIBSecCom',
    [string]$Location = 'eastus2',
    [string]$UamiName = 'mi-tvm-graph-ingest',
    [string]$UamiSubscriptionName = $WorkspaceSubscriptionName,
    [string]$UamiSubscriptionId = '',
    [string]$UamiResourceGroup = $WorkspaceResourceGroup,
    [string]$MachineName = 'WIN11-INTUNE',
    [string]$TvmTable = 'MdeTvmWin11IntuneSingleHost_CL',
    [string]$DcrName = 'dcr-tvm-win11-intune-sh',
    [string]$LogicAppName = 'la-tvm-win11-intune',
    [string]$MdeApiBaseUrl = 'https://api.security.microsoft.com',
    [string]$MdeApiAudience = 'https://api.securitycenter.microsoft.com',
    [int]$LookbackHours = 24,
    [bool]$EnableDailyTableCleanup = $true,
    [int]$TableRetentionInDays = 4,
    [string]$TemplateFile = (Join-Path $PSScriptRoot 'deploy-tvm-machine-win11-intune.bicep'),
    [string]$TableTemplateFile = (Join-Path $PSScriptRoot 'deploy-tvm-machine-win11-intune-table.bicep')
)

$ErrorActionPreference = 'Stop'

function Resolve-SubscriptionId {
    param(
        [string]$Name,
        [string]$Id
    )

    if (-not [string]::IsNullOrWhiteSpace($Id)) {
        return $Id
    }

    Write-Host "Resolving subscription '$Name' to a subscription id..."

    $resolved = $null
    if (Get-Command Get-AzSubscription -ErrorAction SilentlyContinue) {
        try {
            $sub = Get-AzSubscription -SubscriptionName $Name -ErrorAction Stop
            $resolved = $sub.Id
        } catch {
            Write-Warning "Get-AzSubscription failed ($($_.Exception.Message)). Falling back to az CLI."
        }
    } else {
        Write-Warning "Az PowerShell module not found. Falling back to 'az account list'. Install with: Install-Module Az -Scope CurrentUser"
    }

    if ([string]::IsNullOrWhiteSpace($resolved)) {
        $resolved = az account list --query "[?name=='$Name'] | [0].id" -o tsv 2>$null
    }

    if ([string]::IsNullOrWhiteSpace($resolved)) {
        throw "Could not resolve subscription named '$Name'. Connect with Connect-AzAccount or 'az login', or pass the subscription id explicitly."
    }

    Write-Host "Resolved '$Name' -> $resolved"
    return $resolved
}

if (-not (Test-Path -LiteralPath $TemplateFile)) {
    throw "Template file not found: $TemplateFile"
}

if (-not (Test-Path -LiteralPath $TableTemplateFile)) {
    throw "Table template file not found: $TableTemplateFile"
}

if ($LookbackHours -lt 1) {
    throw "LookbackHours must be at least 1."
}

if ($TableRetentionInDays -lt 4) {
    throw "TableRetentionInDays must be at least 4 for an Analytics custom table. The workflow cleanup handles the exact 24-hour window."
}

$SubscriptionId = Resolve-SubscriptionId -Name $SubscriptionName -Id $SubscriptionId
$WorkspaceSubscriptionId = Resolve-SubscriptionId -Name $WorkspaceSubscriptionName -Id $WorkspaceSubscriptionId
$UamiSubscriptionId = Resolve-SubscriptionId -Name $UamiSubscriptionName -Id $UamiSubscriptionId
$workspaceResourceId = "/subscriptions/$WorkspaceSubscriptionId/resourceGroups/$WorkspaceResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"
$enableDailyTableCleanupValue = $EnableDailyTableCleanup.ToString().ToLowerInvariant()
Write-Host "Ensuring resource group '$ResourceGroup' exists in subscription '$SubscriptionName'..."
az group create --name $ResourceGroup --location $Location --subscription $SubscriptionId --only-show-errors | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "az group create failed for '$ResourceGroup' in subscription '$SubscriptionId'."
}

$tableDeployArgs = @(
    'deployment', 'group', 'create',
    '--resource-group', $WorkspaceResourceGroup,
    '--subscription', $WorkspaceSubscriptionId,
    '--template-file', $TableTemplateFile,
    '--parameters',
    "workspaceName=$WorkspaceName",
    "tvmTable=$TvmTable",
    "tableRetentionInDays=$TableRetentionInDays",
    "uamiName=$UamiName",
    "uamiSubscriptionId=$UamiSubscriptionId",
    "uamiResourceGroup=$UamiResourceGroup",
    "enableDailyTableCleanup=$enableDailyTableCleanupValue"
)

Write-Host "Creating/updating table '$TvmTable' in workspace '$WorkspaceName' under subscription '$WorkspaceSubscriptionName'..."
$tableResult = az @tableDeployArgs
if ($LASTEXITCODE -ne 0) {
    throw "az deployment group create failed for the Log Analytics table."
}

$tableResult

$deployArgs = @(
    'deployment', 'group', 'create',
    '--resource-group', $ResourceGroup,
    '--subscription', $SubscriptionId,
    '--template-file', $TemplateFile,
    '--parameters',
    "workspaceResourceId=$workspaceResourceId",
    "location=$Location",
    "uamiName=$UamiName",
    "uamiSubscriptionId=$UamiSubscriptionId",
    "uamiResourceGroup=$UamiResourceGroup",
    "machineName=$MachineName",
    "tvmTable=$TvmTable",
    "dcrName=$DcrName",
    "logicAppName=$LogicAppName",
    "mdeApiBaseUrl=$MdeApiBaseUrl",
    "mdeApiAudience=$MdeApiAudience",
    "lookbackHours=$LookbackHours",
    "enableDailyTableCleanup=$enableDailyTableCleanupValue"
)

Write-Host "Deploying single-host TVM Logic App '$LogicAppName' for '$MachineName' into subscription '$SubscriptionName'..."
$result = az @deployArgs
if ($LASTEXITCODE -ne 0) {
    throw "az deployment group create failed."
}

$result
Write-Host "Deployment complete. Run .\grant-defender-xdr-tvm-permission.ps1 if the shared UAMI does not already have Vulnerability.Read.All."