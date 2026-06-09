targetScope = 'resourceGroup'

@description('Log Analytics workspace that owns the destination custom table.')
param workspaceName string = 'DIBSecCom'

@description('Destination custom table for the single-host WIN11-INTUNE TVM example.')
param tvmTable string = 'MdeTvmWin11IntuneSingleHost_CL'

@description('Analytics table retention in days. The Logic App purge keeps only the latest 24 hours after each run.')
@minValue(4)
param tableRetentionInDays int = 4

@description('Existing user-assigned managed identity name that purges rows older than the active lookback.')
param uamiName string = 'mi-tvm-graph-ingest'

@description('Subscription id of the existing user-assigned managed identity.')
param uamiSubscriptionId string = subscription().subscriptionId

@description('Resource group of the existing user-assigned managed identity.')
param uamiResourceGroup string = resourceGroup().name

@description('Whether to grant Data Purger to the managed identity for daily cleanup.')
param enableDailyTablePurge bool = true

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' existing = {
  name: workspaceName
}

resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  scope: resourceGroup(uamiSubscriptionId, uamiResourceGroup)
  name: uamiName
}

var dataPurgerRoleId = '150f5e0c-0603-4f03-8c7f-cf70034c4e90'

resource tvmCustomTable 'Microsoft.OperationalInsights/workspaces/tables@2025-02-01' = {
  parent: workspace
  name: tvmTable
  properties: {
    schema: {
      name: tvmTable
      columns: [
        { name: 'TimeGenerated', type: 'datetime' }
        { name: 'id', type: 'string' }
        { name: 'deviceId', type: 'string' }
        { name: 'rbacGroupId', type: 'int' }
        { name: 'rbacGroupName', type: 'string' }
        { name: 'deviceName', type: 'string' }
        { name: 'osPlatform', type: 'string' }
        { name: 'osVersion', type: 'string' }
        { name: 'osArchitecture', type: 'string' }
        { name: 'softwareVendor', type: 'string' }
        { name: 'softwareName', type: 'string' }
        { name: 'softwareVersion', type: 'string' }
        { name: 'cveId', type: 'string' }
        { name: 'vulnerabilitySeverityLevel', type: 'string' }
        { name: 'recommendedSecurityUpdate', type: 'string' }
        { name: 'recommendedSecurityUpdateId', type: 'string' }
        { name: 'recommendedSecurityUpdateUrl', type: 'string' }
        { name: 'diskPaths', type: 'string' }
        { name: 'registryPaths', type: 'string' }
        { name: 'lastSeenTimestamp', type: 'string' }
        { name: 'firstSeenTimestamp', type: 'string' }
        { name: 'endOfSupportStatus', type: 'string' }
        { name: 'endOfSupportDate', type: 'string' }
        { name: 'exploitabilityLevel', type: 'string' }
        { name: 'recommendationReference', type: 'string' }
        { name: 'cvssScore', type: 'string' }
        { name: 'securityUpdateAvailable', type: 'string' }
        { name: 'cveMitigationStatus', type: 'string' }
      ]
    }
    retentionInDays: tableRetentionInDays
    plan: 'Analytics'
  }
}

resource workspaceDataPurgerRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (enableDailyTablePurge) {
  scope: workspace
  name: guid(workspace.id, uami.id, dataPurgerRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', dataPurgerRoleId)
    principalId: uami.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

output tableName string = tvmTable
output workspaceResourceId string = workspace.id
output tableRetentionInDays int = tableRetentionInDays
output enableDailyTablePurge bool = enableDailyTablePurge
