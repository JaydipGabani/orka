targetScope = 'resourceGroup'

param prefix string
param location string
param ownershipTags object
param vnetCidr string
param podCidr string
param serviceCidr string
param trustedBuildClientCidr string
param trustedControlVnetCidr string
param builderImageVersion string
param builderAdminUsername string
@secure()
param operatorSshPublicKey string

resource registry 'Microsoft.ContainerRegistry/registries@2025-11-01' = {
  name: 'orkaverif${replace(prefix, 'orka-verify-', '')}'
  location: location
  tags: ownershipTags
  sku: { name: 'Basic' }
  properties: {
    adminUserEnabled: false
    anonymousPullEnabled: false
    publicNetworkAccess: 'Enabled'
    roleAssignmentMode: 'LegacyRegistryPermissions'
  }
}

resource egressIP 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: '${prefix}-egress'
  location: location
  tags: ownershipTags
  sku: { name: 'Standard' }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
  }
}

resource egress 'Microsoft.Network/natGateways@2024-05-01' = {
  name: '${prefix}-egress'
  location: location
  tags: ownershipTags
  sku: { name: 'Standard' }
  properties: {
    idleTimeoutInMinutes: 4
    publicIpAddresses: [{ id: egressIP.id }]
  }
}

resource nodeNSG 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${prefix}-nodes'
  location: location
  tags: ownershipTags
  properties: {
    securityRules: [
      {
        name: 'deny-public-workload-ingress'
        properties: {
          priority: 100
          access: 'Deny'
          direction: 'Inbound'
          protocol: '*'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      {
        name: 'trusted-control-api'
        properties: {
          priority: 110
          access: 'Allow'
          direction: 'Inbound'
          protocol: 'Tcp'
          sourceAddressPrefix: trustedBuildClientCidr
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
        }
      }
      {
        name: 'deny-other-control-ingress'
        properties: {
          priority: 120
          access: 'Deny'
          direction: 'Inbound'
          protocol: '*'
          sourceAddressPrefix: trustedControlVnetCidr
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      {
        name: 'deny-connections-to-control'
        properties: {
          priority: 100
          access: 'Deny'
          direction: 'Outbound'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: trustedControlVnetCidr
          destinationPortRange: '*'
        }
      }
    ]
  }
}

resource controlPlaneIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${prefix}-aks-control-plane'
  location: location
  tags: ownershipTags
}

var networkRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4d97b98b-1d4f-4787-a291-c67834d212e7')

resource nodeSecurityAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(nodeNSG.id, controlPlaneIdentity.id, networkRoleId)
  scope: nodeNSG
  properties: {
    principalId: controlPlaneIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: networkRoleId
  }
}

resource egressAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(egress.id, controlPlaneIdentity.id, networkRoleId)
  scope: egress
  properties: {
    principalId: controlPlaneIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: networkRoleId
  }
}

module compute './compute-core.bicep' = {
  name: 'isolated-verification-compute'
  params: {
    prefix: prefix
    location: location
    ownershipTags: ownershipTags
    vnetCidr: vnetCidr
    podCidr: podCidr
    serviceCidr: serviceCidr
    trustedBuildClientCidr: trustedBuildClientCidr
    builderImageVersion: builderImageVersion
    builderAdminUsername: builderAdminUsername
    operatorSshPublicKey: operatorSshPublicKey
    controlPlanePrincipalId: controlPlaneIdentity.properties.principalId
  }
  dependsOn: [
    nodeSecurityAccess
    egressAccess
  ]
}

output clusterId string = compute.outputs.clusterId
output builderId string = compute.outputs.builderId
output vnetId string = compute.outputs.vnetId
output registryId string = registry.id
