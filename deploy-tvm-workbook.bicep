targetScope = 'resourceGroup'

@description('Stable workbook resource name (GUID). Keep constant across redeploys to update in place.')
param workbookName string = '4a98f09f-4a20-40be-b533-64b0bf2da438'

@description('Azure region for the workbook resource.')
param location string = 'eastus2'

@description('Workbook display name shown in the Sentinel UI.')
param displayName string = 'TVM-By-Region'

@description('Workbook category. Use "sentinel" so it appears in the Sentinel workbook gallery.')
param category string = 'sentinel'

@description('Log Analytics workspace name that backs the workbook.')
param workspaceName string = 'DIBSecCom'

@description('Resource group of the Log Analytics workspace. Defaults to the deployment resource group.')
param workspaceResourceGroup string = resourceGroup().name

@description('Subscription id of the Log Analytics workspace. Defaults to the current deployment subscription.')
param workspaceSubscriptionId string = subscription().subscriptionId

@description('Tags applied to the workbook resource.')
param workbookTags object = {
  'hidden-title': 'TVM-By-Region'
}

// Computed workspace resource id used as the workbook sourceId and substituted
// into any literal references inside the workbook JSON. This removes all
// hard-coded subscription/RG/workspace strings from the deployable artifact.
var sourceId = '/subscriptions/${workspaceSubscriptionId}/resourceGroups/${workspaceResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${workspaceName}'

// Workbook JSON shipped with this repo embeds the original workspace path in
// `fallbackResourceIds` and other locations. Patch that path to the current
// target workspace so the file is portable across tenants/subscriptions.
var rawWorkbookJson      = loadTextContent('MDE_TVM_Regional_Vulnerability_Workbook.workbook.json')
var legacyWorkspaceLower = '/subscriptions/192ad012-896e-4f14-8525-c37a2a9640f9/resourceGroups/Sentinel/providers/Microsoft.OperationalInsights/workspaces/DIBSecCom'
var legacyWorkspaceUpper = '/subscriptions/192ad012-896e-4f14-8525-c37a2a9640f9/resourcegroups/sentinel/providers/microsoft.operationalinsights/workspaces/dibseccom'
var serializedData       = replace(replace(rawWorkbookJson, legacyWorkspaceLower, sourceId), legacyWorkspaceUpper, sourceId)

resource workbook 'Microsoft.Insights/workbooks@2022-04-01' = {
  name: workbookName
  location: location
  kind: 'shared'
  tags: workbookTags
  properties: {
    displayName: displayName
    serializedData: serializedData
    version: 'Notebook/1.0'
    category: category
    sourceId: sourceId
  }
}

output workbookResourceId string = workbook.id
output sourceId string = sourceId
