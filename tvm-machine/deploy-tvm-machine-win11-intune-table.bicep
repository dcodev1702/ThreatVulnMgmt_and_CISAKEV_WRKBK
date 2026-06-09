targetScope = 'resourceGroup'

@description('Log Analytics workspace that owns the destination custom table.')
param workspaceName string = 'DIBSecCom'

@description('Destination custom table for the single-host WIN11-INTUNE TVM example.')
param tvmTable string = 'MdeTvmWin11IntuneSingleHost_CL'

@description('Analytics table retention in days. The Logic App cleanup keeps only the latest 24 hours after each run.')
@minValue(4)
param tableRetentionInDays int = 4

@description('Existing user-assigned managed identity name that deletes rows older than the active lookback.')
param uamiName string = 'mi-tvm-graph-ingest'

@description('Subscription id of the existing user-assigned managed identity.')
param uamiSubscriptionId string = subscription().subscriptionId

@description('Resource group of the existing user-assigned managed identity.')
param uamiResourceGroup string = resourceGroup().name

@description('Whether to grant Delete Data API permissions to the managed identity for daily cleanup.')
param enableDailyTableCleanup bool = true

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' existing = {
  name: workspaceName
}

resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  scope: resourceGroup(uamiSubscriptionId, uamiResourceGroup)
  name: uamiName
}

resource tableDeleteDataRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = if (enableDailyTableCleanup) {
  name: guid(resourceGroup().id, 'mde-tvm-single-host-delete-data', tvmTable)
  properties: {
    roleName: 'MDE TVM Single Host Delete Data ${uniqueString(resourceGroup().id, tvmTable)}'
    description: 'Can delete rows from the single-host TVM custom table by using the Log Analytics Delete Data API.'
    type: 'CustomRole'
    assignableScopes: [
      resourceGroup().id
    ]
    permissions: [
      {
        actions: [
          'Microsoft.OperationalInsights/workspaces/read'
          'Microsoft.OperationalInsights/workspaces/tables/read'
          'Microsoft.OperationalInsights/workspaces/tables/deleteData/action'
        ]
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
  }
}

resource tvmCustomTable 'Microsoft.OperationalInsights/workspaces/tables@2025-02-01' = {
  parent: workspace
  name: tvmTable
  properties: {
    schema: {
      name: tvmTable
      columns: [
        { name: 'TimeGenerated', type: 'datetime' }
        { name: 'ingestionRunTime', type: 'datetime' }
        { name: 'findingKey', type: 'string' }
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

resource workspaceCleanupRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (enableDailyTableCleanup) {
  scope: workspace
  name: guid(workspace.id, uami.id, tableDeleteDataRole.id)
  properties: {
    roleDefinitionId: tableDeleteDataRole.id
    principalId: uami.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

output tableName string = tvmTable
output workspaceResourceId string = workspace.id
output tableRetentionInDays int = tableRetentionInDays
output enableDailyTableCleanup bool = enableDailyTableCleanup
