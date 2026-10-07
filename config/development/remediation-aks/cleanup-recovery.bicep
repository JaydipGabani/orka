targetScope = 'resourceGroup'

param prefix string
param location string
resource account 'Microsoft.Automation/automationAccounts@2024-10-23' existing = {
  name: '${prefix}-reaper'
}

// Existing account properties are never PUT during recovery. Provider-added
// encryption/runtime defaults must not be removed by replaying account creation.
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
