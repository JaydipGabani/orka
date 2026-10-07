targetScope = 'subscription'

@minLength(6)
@maxLength(12)
param suffix string
param owner string
param cleanupReceipt string
param sourceDigest string

@allowed(['eastus2'])
param location string = 'eastus2'

var prefix = 'orka-verify-${suffix}'
var tags = {
  'orka-purpose': 'isolated-remediation-verification'
  'orka-owner': owner
  'orka-deployment': prefix
  'orka-cleanup-receipt': cleanupReceipt
  'orka-source-digest': sourceDigest
  'orka-budget-start-utc': 'pending'
  'orka-expires-at-utc': 'pending'
}

resource verificationGroup 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: 'rg-${prefix}'
  location: location
  tags: tags
}

resource cleanupGroup 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: 'rg-${prefix}-cleanup'
  location: location
  tags: tags
}

module service './cleanup-service.bicep' = {
  name: 'bounded-cleanup-service'
  scope: cleanupGroup
  params: {
    prefix: prefix
    location: location
    ownershipTags: tags
  }
}

output verificationResourceGroupId string = verificationGroup.id
output cleanupResourceGroupId string = cleanupGroup.id
output automationAccountId string = service.outputs.accountId
output principalId string = service.outputs.principalId
output tenantId string = service.outputs.tenantId
