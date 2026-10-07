targetScope = 'subscription'

param suffix string
param principalId string
param includeNodeGroup bool = false

var prefix = 'orka-verify-${suffix}'
var resourceRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '94877a25-7520-40c5-9c42-68e02e4758bd')
var readerRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'acdd72a7-3385-48ef-bd42-f606fba81ae7')
var networkRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4d97b98b-1d4f-4787-a291-c67834d212e7')

resource verificationGroup 'Microsoft.Resources/resourceGroups@2024-03-01' existing = {
  name: 'rg-${prefix}'
}

resource nodeGroup 'Microsoft.Resources/resourceGroups@2024-03-01' existing = {
  name: 'rg-${prefix}-nodes'
}

resource groupMetadataAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, readerRoleId, principalId)
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: readerRoleId
  }
}

module verificationAccess './cleanup-group-binding.bicep' = {
  scope: verificationGroup
  name: 'verification-cleanup-access'
  params: {
    principalId: principalId
    roleDefinitionId: resourceRoleId
  }
}

module nodeAccess './cleanup-group-binding.bicep' = if (includeNodeGroup) {
  scope: nodeGroup
  name: 'node-cleanup-access'
  params: {
    principalId: principalId
    roleDefinitionId: resourceRoleId
  }
}

output cleanupResourceRoleId string = resourceRoleId
output peeringRoleId string = networkRoleId
output verificationAssignmentId string = verificationAccess.outputs.assignmentId
output groupMetadataRoleId string = readerRoleId
output groupMetadataAssignmentId string = groupMetadataAccess.id
output nodeAssignmentId string = includeNodeGroup ? nodeAccess!.outputs.assignmentId : ''
