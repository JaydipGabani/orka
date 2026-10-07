targetScope = 'resourceGroup'

param prefix string
param location string
param ownershipTags object

var childOwnershipTags = {
  'orka-owner': ownershipTags['orka-owner']
  'orka-deployment': ownershipTags['orka-deployment']
  'orka-cleanup-receipt': ownershipTags['orka-cleanup-receipt']
}

resource account 'Microsoft.Automation/automationAccounts@2024-10-23' existing = {
  name: '${prefix}-reaper'
}

// Existing account properties are never PUT during recovery. Provider-added
// encryption/runtime defaults must not be removed by replaying account creation.
resource runtime 'Microsoft.Automation/automationAccounts/runtimeEnvironments@2024-10-23' = {
  parent: account
  name: 'PowerShell74'
  location: location
  tags: childOwnershipTags
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
  tags: childOwnershipTags
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
