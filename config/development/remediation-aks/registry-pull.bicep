targetScope = 'resourceGroup'

param registryName string
param controlKubeletObjectId string
param verificationKubeletObjectId string

resource registry 'Microsoft.ContainerRegistry/registries@2025-11-01' existing = {
  name: registryName
}

var pullRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '7f951dda-4ed3-4680-a7ca-43fe172d538d'
)

resource controlPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: registry
  name: guid(registry.id, pullRoleId, controlKubeletObjectId)
  properties: {
    principalId: controlKubeletObjectId
    principalType: 'ServicePrincipal'
    roleDefinitionId: pullRoleId
  }
}

resource verificationPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: registry
  name: guid(registry.id, pullRoleId, verificationKubeletObjectId)
  properties: {
    principalId: verificationKubeletObjectId
    principalType: 'ServicePrincipal'
    roleDefinitionId: pullRoleId
  }
}

output controlAssignmentId string = controlPull.id
output verificationAssignmentId string = verificationPull.id
