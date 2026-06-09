targetScope = 'resourceGroup'

@description('Log Analytics workspace that owns the destination custom table.')
param workspaceResourceId string

@description('Destination custom table for the single-host WIN11-INTUNE TVM example.')
param tvmTable string = 'MdeTvmWin11IntuneSingleHost_CL'

@description('Existing user-assigned managed identity name shared with the main TVM ingest Logic App.')
param uamiName string = 'mi-tvm-graph-ingest'

@description('Subscription id of the existing user-assigned managed identity.')
param uamiSubscriptionId string = subscription().subscriptionId

@description('Resource group of the existing user-assigned managed identity. Defaults to the deployment resource group.')
param uamiResourceGroup string = resourceGroup().name

@description('Data Collection Rule name for the single-host example.')
param dcrName string = 'dcr-tvm-win11-intune-sh'

@description('Logic App (Consumption) name for the single-host example.')
param logicAppName string = 'la-tvm-win11-intune'

@description('Azure region for new resources. Must equal the workspace region for the DCR (Logs Ingestion).')
param location string = 'eastus2'

@description('Defender XDR deviceName filter value.')
param machineName string = 'WIN11-INTUNE'

@description('Commercial Microsoft Defender XDR API base URL.')
param mdeApiBaseUrl string = 'https://api.security.microsoft.com'

@description('Commercial Microsoft Defender for Endpoint managed identity token audience.')
param mdeApiAudience string = 'https://api.securitycenter.microsoft.com'

@description('Rows requested from the Defender XDR API per page.')
param pageSize int = 50000

@description('Only TVM rows with lastSeenTimestamp inside this many hours are ingested and retained.')
param lookbackHours int = 24

@description('Whether the Logic App deletes table rows older than the lookback after each run.')
param enableDailyTableCleanup bool = true

var streamName = 'Custom-${tvmTable}'

resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  scope: resourceGroup(uamiSubscriptionId, uamiResourceGroup)
  name: uamiName
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dcrName
  location: location
  kind: 'Direct'
  properties: {
    description: 'Direct ingestion of WIN11-INTUNE Defender XDR TVM rows into ${tvmTable}.'
    streamDeclarations: {
      '${streamName}': {
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
    }
    destinations: {
      logAnalytics: [
        {
          name: 'sentinelWorkspace'
          workspaceResourceId: workspaceResourceId
        }
      ]
    }
    dataFlows: [
      {
        streams: [ streamName ]
        destinations: [ 'sentinelWorkspace' ]
        transformKql: 'source | where TimeGenerated >= ago(${lookbackHours}h)'
        outputStream: streamName
      }
    ]
  }
}

var monitoringMetricsPublisherRoleId = '3913510d-42f4-4e42-8a64-420c390055eb'

resource dcrMetricsPublisherRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: dcr
  name: guid(dcr.id, uami.id, monitoringMetricsPublisherRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringMetricsPublisherRoleId)
    principalId: uami.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource logicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: logicAppName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${uami.id}': {}
    }
  }
  properties: {
    state: 'Enabled'
    definition: loadJsonContent('logicapp-machine.json')
    parameters: {
      UamiResourceId: {
        value: uami.id
      }
      DcrLogsIngestionEndpoint: {
        value: dcr.properties.endpoints.logsIngestion
      }
      DcrImmutableId: {
        value: dcr.properties.immutableId
      }
      WorkspaceResourceId: {
        value: workspaceResourceId
      }
      StreamName: {
        value: streamName
      }
      TvmTable: {
        value: tvmTable
      }
      MdeApiBaseUrl: {
        value: mdeApiBaseUrl
      }
      MdeApiAudience: {
        value: mdeApiAudience
      }
      MdeMachineName: {
        value: machineName
      }
      PageSize: {
        value: pageSize
      }
      LookbackHours: {
        value: lookbackHours
      }
      EnableDailyTableCleanup: {
        value: enableDailyTableCleanup
      }
    }
  }
  dependsOn: [
    dcrMetricsPublisherRole
  ]
}

output tableName string = tvmTable
output streamName string = streamName
output workspaceResourceId string = workspaceResourceId
output uamiResourceId string = uami.id
output uamiPrincipalId string = uami.properties.principalId
output dcrResourceId string = dcr.id
output dcrImmutableId string = dcr.properties.immutableId
output dcrLogsIngestionEndpoint string = dcr.properties.endpoints.logsIngestion
output logicAppResourceId string = logicApp.id
output machineName string = machineName
output lookbackHours int = lookbackHours
output enableDailyTableCleanup bool = enableDailyTableCleanup
output mdeApiBaseUrl string = mdeApiBaseUrl
