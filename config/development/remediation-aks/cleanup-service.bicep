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
  tags: ownershipTags
  properties: {
    runtime: { language: 'PowerShell', version: '7.4' }
    defaultPackages: {}
    description: 'Bounded ARM cleanup using built-in HTTP/JSON only; no Az context or Hybrid Worker.'
  }
}

resource runbook 'Microsoft.Automation/automationAccounts/runbooks@2024-10-23' = {
  parent: account
  name: 'ExactFoundationCleanup'
  location: location
  tags: ownershipTags
  properties: {
    runbookType: 'PowerShell'
    runtimeEnvironment: runtime.name
    draft: {}
    logVerbose: false
    logProgress: false
    logActivityTrace: 0
    description: 'Review-pinned code is uploaded and published separately before schedules are armed.'
  }
}

output accountId string = account.id
output principalId string = account.identity.principalId
output tenantId string = account.identity.tenantId
