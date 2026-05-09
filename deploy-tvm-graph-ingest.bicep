// Graph runHuntingQuery -> Logs Ingestion DCR -> TvmRegional_CL
//
// Architecture:
//   Logic App Consumption (UAMI auth) -> daily Recurrence trigger
//     -> HTTP POST graph.microsoft.com/v1.0/security/runHuntingQuery (audience https://graph.microsoft.com)
//     -> Select transform + Until-loop chunking (1000 rows / batch)
//     -> HTTP POST DCR.endpoints.logsIngestion (audience https://monitor.azure.com)
//   DCR has kind=Direct so logsIngestion endpoint is built-in (no DCE).
//   UAMI is granted:
//     - Microsoft Graph app role ThreatHunting.Read.All  (granted out-of-band by grant-graph-permission.ps1)
//     - Monitoring Metrics Publisher on the DCR          (granted by this template)
//
// No shared keys, no SAS, no Function keys, no app secrets.
//
// Deploy:
//   az deployment group create -g Sentinel `
//     --subscription 192ad012-896e-4f14-8525-c37a2a9640f9 `
//     --template-file .\deploy-tvm-graph-ingest.bicep
//
// After deploy, run:
//   .\grant-graph-permission.ps1   (idempotent)

@description('Log Analytics workspace that owns the destination custom table.')
param workspaceName string = 'DIBSecCom'

@description('Destination custom table that the workbook reads.')
param destinationTable string = 'TvmRegional_CL'

@description('Destination custom table for the CISA KEV catalog feed.')
param kevTable string = 'CisaKev_CL'

@description('User-assigned managed identity name.')
param uamiName string = 'mi-tvm-graph-ingest'

@description('Data Collection Rule name.')
param dcrName string = 'dcr-tvm-graph-ingest'

@description('Logic App (Consumption) name.')
param logicAppName string = 'la-tvm-graph-ingest'

@description('Azure region for new resources. Must equal the workspace region for the DCR (Logs Ingestion).')
param location string = 'eastus2'

@description('KQL query sent to the Defender XDR advanced hunting tier via Microsoft Graph.')
param huntingQuery string = 'DeviceTvmSoftwareVulnerabilities | where isnotempty(DeviceId) | project DeviceId, DeviceName, SoftwareVendor=tostring(SoftwareVendor), SoftwareName=tostring(SoftwareName), SoftwareVersion=tostring(SoftwareVersion), CveId, VulnerabilitySeverityLevel=tostring(VulnerabilitySeverityLevel), RecommendedSecurityUpdate=tostring(RecommendedSecurityUpdate), RecommendedSecurityUpdateId=tostring(RecommendedSecurityUpdateId), OSPlatform, OSVersion, CveTags'

@description('Rows per Logs Ingestion POST. Logs Ingestion API caps at 1MB / request; ~1000 TVM rows is well under.')
param chunkSize int = 1000

@description('Public CISA Known Exploited Vulnerabilities feed URL (no auth).')
param kevFeedUrl string = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

@description('Rows per Logs Ingestion POST for KEV (smaller chunks because shortDescription/requiredAction are long strings).')
param kevChunkSize int = 500

var streamName = 'Custom-${destinationTable}'
var kevStreamName = 'Custom-${kevTable}'

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' existing = {
  name: workspaceName
}

// User-assigned managed identity used by the Logic App for both
// Graph runHuntingQuery and Logs Ingestion calls.
resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: uamiName
  location: location
}

// Custom table for the CISA Known Exploited Vulnerabilities feed. The DCR
// validates that the destination table exists at deployment time, so this
// must be created before the DCR's CisaKev dataFlow is added.
// (TvmRegional_CL was created earlier by the now-deleted Summary Rule.)
resource kevCustomTable 'Microsoft.OperationalInsights/workspaces/tables@2025-02-01' = {
  parent: workspace
  name: kevTable
  properties: {
    schema: {
      name: kevTable
      columns: [
        { name: 'TimeGenerated', type: 'datetime' }
        { name: 'CatalogVersion', type: 'string' }
        { name: 'CatalogDateReleased', type: 'datetime' }
        { name: 'CveId', type: 'string' }
        { name: 'VendorProject', type: 'string' }
        { name: 'Product', type: 'string' }
        { name: 'VulnerabilityName', type: 'string' }
        { name: 'DateAdded', type: 'datetime' }
        { name: 'ShortDescription', type: 'string' }
        { name: 'RequiredAction', type: 'string' }
        { name: 'DueDate', type: 'datetime' }
        { name: 'KnownRansomwareCampaignUse', type: 'string' }
        { name: 'Notes', type: 'string' }
        { name: 'Cwes', type: 'dynamic' }
      ]
    }
    retentionInDays: 90
    plan: 'Analytics'
  }
}

// Direct-ingestion DCR with built-in logsIngestion endpoint.
// streamDeclarations columns must match the JSON the Logic App POSTs.
resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dcrName
  location: location
  kind: 'Direct'
  dependsOn: [
    kevCustomTable
  ]
  properties: {
    description: 'Direct ingestion of pruned DeviceTvmSoftwareVulnerabilities rows from Microsoft Graph runHuntingQuery into ${destinationTable} for the TVM-By-Region workbook.'
    streamDeclarations: {
      '${streamName}': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'DeviceId', type: 'string' }
          { name: 'DeviceName', type: 'string' }
          { name: 'SoftwareVendor', type: 'string' }
          { name: 'SoftwareName', type: 'string' }
          { name: 'SoftwareVersion', type: 'string' }
          { name: 'CveId', type: 'string' }
          { name: 'VulnerabilitySeverityLevel', type: 'string' }
          { name: 'RecommendedSecurityUpdate', type: 'string' }
          { name: 'RecommendedSecurityUpdateId', type: 'string' }
          { name: 'OSPlatform', type: 'string' }
          { name: 'OSVersion', type: 'string' }
          { name: 'CveTags', type: 'dynamic' }
        ]
      }
      '${kevStreamName}': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'CatalogVersion', type: 'string' }
          { name: 'CatalogDateReleased', type: 'datetime' }
          { name: 'CveId', type: 'string' }
          { name: 'VendorProject', type: 'string' }
          { name: 'Product', type: 'string' }
          { name: 'VulnerabilityName', type: 'string' }
          { name: 'DateAdded', type: 'datetime' }
          { name: 'ShortDescription', type: 'string' }
          { name: 'RequiredAction', type: 'string' }
          { name: 'DueDate', type: 'datetime' }
          { name: 'KnownRansomwareCampaignUse', type: 'string' }
          { name: 'Notes', type: 'string' }
          { name: 'Cwes', type: 'dynamic' }
        ]
      }
    }
    destinations: {
      logAnalytics: [
        {
          name: 'sentinelWorkspace'
          workspaceResourceId: workspace.id
        }
      ]
    }
    dataFlows: [
      {
        streams: [ streamName ]
        destinations: [ 'sentinelWorkspace' ]
        transformKql: 'source'
        outputStream: streamName
      }
      {
        streams: [ kevStreamName ]
        destinations: [ 'sentinelWorkspace' ]
        transformKql: 'source'
        outputStream: kevStreamName
      }
    ]
  }
}

// Monitoring Metrics Publisher (3913510d-42f4-4e42-8a64-420c390055eb) on the DCR for the UAMI.
// This is the role required by the Logs Ingestion API.
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

// Logic App (Consumption) with UAMI assigned at the resource level.
// Workflow definition is loaded from tvm-graph-ingest.workflow.json and
// runtime parameters are bound here.
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
    definition: loadJsonContent('tvm-graph-ingest.workflow.json')
    parameters: {
      uamiResourceId: {
        value: uami.id
      }
      dcrLogsIngestionEndpoint: {
        value: dcr.properties.endpoints.logsIngestion
      }
      dcrImmutableId: {
        value: dcr.properties.immutableId
      }
      streamName: {
        value: streamName
      }
      huntingQuery: {
        value: huntingQuery
      }
      chunkSize: {
        value: chunkSize
      }
      kevStreamName: {
        value: kevStreamName
      }
      kevFeedUrl: {
        value: kevFeedUrl
      }
      kevChunkSize: {
        value: kevChunkSize
      }
    }
  }
  dependsOn: [
    dcrMetricsPublisherRole
  ]
}

output uamiResourceId string = uami.id
output uamiPrincipalId string = uami.properties.principalId
output uamiClientId string = uami.properties.clientId
output dcrResourceId string = dcr.id
output dcrImmutableId string = dcr.properties.immutableId
output dcrLogsIngestionEndpoint string = dcr.properties.endpoints.logsIngestion
output streamName string = streamName
output kevStreamName string = kevStreamName
output logicAppResourceId string = logicApp.id
