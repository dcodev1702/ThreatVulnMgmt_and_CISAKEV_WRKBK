targetScope = 'resourceGroup'

param workbookName string = '4a98f09f-4a20-40be-b533-64b0bf2da438'
param location string = 'eastus2'
param displayName string = 'TVM-By-Region'
param category string = 'sentinel'
param sourceId string = '/subscriptions/192ad012-896e-4f14-8525-c37a2a9640f9/resourcegroups/sentinel/providers/microsoft.operationalinsights/workspaces/dibseccom'
param workbookTags object = {
  'hidden-title': 'TVM-By-Region'
}

var serializedData = loadTextContent('MDE_TVM_Regional_Vulnerability_Workbook.workbook.json')

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
