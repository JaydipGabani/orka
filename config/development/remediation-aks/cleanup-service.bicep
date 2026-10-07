targetScope = 'resourceGroup'

param prefix string
param location string
param ownershipTags object

resource account 'Microsoft.Automation/automationAccounts@2024-10-23' = {
  name: '${prefix}-reaper'
  location: location
  tags: ownershipTags
  identity: { type: 'SystemAssigned' }
  properties: {
    sku: { name: 'Basic' }
    disableLocalAuth: true
    publicNetworkAccess: false
  }
}

resource runtime 'Microsoft.Automation/automationAccounts/runtimeEnvironments@2024-10-23' = {
  parent: account
  name: 'PowerShell74'
  location: location
  properties: {
    runtime: { language: 'PowerShell', version: '7.4' }
    defaultPackages: {}
  }
}

resource runbook 'Microsoft.Automation/automationAccounts/runbooks@2024-10-23' = {
  parent: account
  name: 'ExactFoundationCleanup'
  location: location
  properties: {
    runbookType: 'PowerShell'
    runtimeEnvironment: runtime.name
    draft: {}
    logVerbose: false
    logProgress: false
    logActivityTrace: 0
  }
}

output accountId string = account.id
output principalId string = account.identity.principalId
output tenantId string = account.identity.tenantId
