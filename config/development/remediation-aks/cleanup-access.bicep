targetScope = 'subscription'

param suffix string
param principalId string
param resourceRoleGuid string
param peeringRoleGuid string
param groupMetadataRoleGuid string
param peerMetadataRoleGuid string
param controlResourceGroup string
param includeNodeGroup bool = false

var prefix = 'orka-verify-${suffix}'

resource verificationGroup 'Microsoft.Resources/resourceGroups@2024-03-01' existing = {
  name: 'rg-${prefix}'
}

resource nodeGroup 'Microsoft.Resources/resourceGroups@2024-03-01' existing = {
  name: 'rg-${prefix}-nodes'
}

resource controlGroup 'Microsoft.Resources/resourceGroups@2024-03-01' existing = {
  name: controlResourceGroup
}

resource resourceRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: resourceRoleGuid
  properties: {
    roleName: '${prefix}-resource-cleanup'
    description: 'Read and delete only dedicated verification resources. No create, IAM mutation, or VMSS operation.'
    type: 'CustomRole'
    assignableScopes: includeNodeGroup ? [verificationGroup.id, nodeGroup.id] : [verificationGroup.id]
    permissions: [
      {
        actions: [
          'Microsoft.Resources/subscriptions/resourceGroups/read'
          'Microsoft.Resources/subscriptions/resourceGroups/delete'
          'Microsoft.Resources/subscriptions/resourceGroups/resources/read'
          'Microsoft.Resources/deployments/read'
          'Microsoft.Resources/deployments/operations/read'
          'Microsoft.ContainerService/managedClusters/read'
          'Microsoft.ContainerService/managedClusters/delete'
          'Microsoft.Compute/virtualMachines/read'
          'Microsoft.Compute/virtualMachines/instanceView/read'
          'Microsoft.Compute/virtualMachines/delete'
          'Microsoft.Authorization/permissions/read'
        ]
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
  }
}

resource peerRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: peeringRoleGuid
  properties: {
    roleName: '${prefix}-peering-cleanup'
    description: 'Read/delete only the exact new control-side peering through a child-resource assignment.'
    type: 'CustomRole'
    assignableScopes: [controlGroup.id]
    permissions: [
      {
        actions: [
          'Microsoft.Network/virtualNetworks/virtualNetworkPeerings/read'
          'Microsoft.Network/virtualNetworks/virtualNetworkPeerings/delete'
        ]
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
  }
}

resource groupMetadataRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: groupMetadataRoleGuid
  properties: {
    roleName: '${prefix}-group-metadata-read'
    description: 'Approved group-level metadata only, to distinguish post-delete absence from lost child-scope authorization.'
    type: 'CustomRole'
    assignableScopes: [subscription().id]
    permissions: [
      {
        actions: ['Microsoft.Resources/subscriptions/resourceGroups/read']
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
  }
}

resource peerMetadataRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: peerMetadataRoleGuid
  properties: {
    roleName: '${prefix}-peering-metadata-read'
    description: 'Approved peering metadata only; assigned to the exact control VNet for post-delete verification.'
    type: 'CustomRole'
    assignableScopes: [controlGroup.id]
    permissions: [
      {
        actions: ['Microsoft.Network/virtualNetworks/virtualNetworkPeerings/read']
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
  }
}

resource groupMetadataAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, groupMetadataRole.id, principalId)
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: groupMetadataRole.id
  }
}

module verificationAccess './cleanup-group-binding.bicep' = {
  scope: verificationGroup
  name: 'verification-cleanup-access'
  params: {
    principalId: principalId
    roleDefinitionId: resourceRole.id
  }
}

module nodeAccess './cleanup-group-binding.bicep' = if (includeNodeGroup) {
  scope: nodeGroup
  name: 'node-cleanup-access'
  params: {
    principalId: principalId
    roleDefinitionId: resourceRole.id
  }
}

output resourceRoleId string = resourceRole.id
output peeringRoleId string = peerRole.id
output verificationAssignmentId string = verificationAccess.outputs.assignmentId
output groupMetadataRoleId string = groupMetadataRole.id
output peerMetadataRoleId string = peerMetadataRole.id
output groupMetadataAssignmentId string = groupMetadataAccess.id
output nodeAssignmentId string = includeNodeGroup ? nodeAccess!.outputs.assignmentId : ''
