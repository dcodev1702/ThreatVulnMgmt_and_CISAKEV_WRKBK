targetScope = 'resourceGroup'

@description('Log Analytics workspace that owns the destination custom table.')
param workspaceName string = 'DIBSecCom'

@description('Destination custom table for the single-host WIN11-INTUNE TVM example.')
param tvmTable string = 'MdeTvmWin11IntuneSingleHost_CL'

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' existing = {
  name: workspaceName
}

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
    retentionInDays: 365
    plan: 'Analytics'
  }
}

output tableName string = tvmTable
output workspaceResourceId string = workspace.id
