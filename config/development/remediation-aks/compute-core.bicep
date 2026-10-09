targetScope = 'resourceGroup'

param prefix string
param location string
param ownershipTags object
param vnetCidr string
param podCidr string
param serviceCidr string
param trustedBuildClientCidr string
param builderImageVersion string
param builderAdminUsername string
@secure()
param operatorSshPublicKey string
@minLength(36)
@maxLength(36)
param controlPlanePrincipalId string

var nodeSubnetCidr = cidrSubnet(vnetCidr, 22, 0)
var builderSubnetCidr = cidrSubnet(vnetCidr, 27, 128)
var builderPrivateIP = cidrHost(builderSubnetCidr, 4)
var networkRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4d97b98b-1d4f-4787-a291-c67834d212e7')

resource registry 'Microsoft.ContainerRegistry/registries@2025-11-01' existing = {
  name: 'orkaverif${replace(prefix, 'orka-verify-', '')}'
}

resource egressIP 'Microsoft.Network/publicIPAddresses@2024-05-01' existing = {
  name: '${prefix}-egress'
}

resource egress 'Microsoft.Network/natGateways@2024-05-01' existing = {
  name: '${prefix}-egress'
}

resource nodeNSG 'Microsoft.Network/networkSecurityGroups@2024-05-01' existing = {
  name: '${prefix}-nodes'
}

resource controlPlaneIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  name: '${prefix}-aks-control-plane'
}

resource builderNSG 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${prefix}-builder'
  location: location
  tags: ownershipTags
  properties: {
    securityRules: [
      {
        name: 'trusted-build-client-mtls'
        properties: {
          priority: 100
          access: 'Allow'
          direction: 'Inbound'
          protocol: 'Tcp'
          sourceAddressPrefix: trustedBuildClientCidr
          sourcePortRange: '*'
          destinationAddressPrefix: builderPrivateIP
          destinationPortRange: '1234'
        }
      }
      {
        name: 'deny-other-ingress'
        properties: {
          priority: 200
          access: 'Deny'
          direction: 'Inbound'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      // Azure platform DNS bypasses NSGs; AzurePlatformDNS only supports Deny opt-outs.
      {
        name: 'deny-lateral-connections'
        properties: {
          priority: 110
          access: 'Deny'
          direction: 'Outbound'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          destinationPortRange: '*'
        }
      }
      {
        name: 'https-egress'
        properties: {
          priority: 120
          access: 'Allow'
          direction: 'Outbound'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'Internet'
          destinationPortRange: '443'
        }
      }
      {
        name: 'deny-other-internet-egress'
        properties: {
          priority: 200
          access: 'Deny'
          direction: 'Outbound'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'Internet'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${prefix}-vnet'
  location: location
  tags: ownershipTags
  properties: {
    addressSpace: { addressPrefixes: [vnetCidr] }
    subnets: [
      {
        name: 'nodes'
        properties: {
          addressPrefix: nodeSubnetCidr
          networkSecurityGroup: { id: nodeNSG.id }
          natGateway: { id: egress.id }
          defaultOutboundAccess: false
          privateEndpointNetworkPolicies: 'NetworkSecurityGroupEnabled'
        }
      }
      {
        name: 'builder'
        properties: {
          addressPrefix: builderSubnetCidr
          networkSecurityGroup: { id: builderNSG.id }
          natGateway: { id: egress.id }
          defaultOutboundAccess: false
        }
      }
    ]
  }
}

resource networkAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vnet.id, controlPlaneIdentity.id, networkRoleId)
  scope: vnet
  properties: {
    principalId: controlPlanePrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: networkRoleId
  }
}

resource cluster 'Microsoft.ContainerService/managedClusters@2025-07-01' = {
  name: '${prefix}-aks'
  location: location
  tags: ownershipTags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${controlPlaneIdentity.id}': {} }
  }
  sku: { name: 'Base', tier: 'Free' }
  properties: {
    kubernetesVersion: '1.35.8'
    dnsPrefix: prefix
    nodeResourceGroup: 'rg-${prefix}-nodes'
    enableRBAC: true
    disableLocalAccounts: true
    aadProfile: {
      managed: true
      enableAzureRBAC: true
      tenantID: subscription().tenantId
    }
    apiServerAccessProfile: {
      enablePrivateCluster: true
      enablePrivateClusterPublicFQDN: false
      privateDNSZone: 'system'
      disableRunCommand: true
    }
    oidcIssuerProfile: { enabled: true }
    securityProfile: { workloadIdentity: { enabled: true } }
    workloadAutoScalerProfile: { keda: { enabled: false } }
    autoUpgradeProfile: {
      upgradeChannel: 'none'
      nodeOSUpgradeChannel: 'None'
    }
    agentPoolProfiles: [
      {
        name: 'verify'
        mode: 'System'
        type: 'VirtualMachineScaleSets'
        count: 2
        vmSize: 'Standard_D4s_v5'
        osType: 'Linux'
        osSKU: 'Ubuntu'
        osDiskSizeGB: 64
        osDiskType: 'Managed'
        enableAutoScaling: false
        maxPods: 30
        orchestratorVersion: '1.35.8'
        vnetSubnetID: resourceId('Microsoft.Network/virtualNetworks/subnets', vnet.name, 'nodes')
        kubeletConfig: { podMaxPids: 512 }
        upgradeSettings: { maxSurge: '1', maxUnavailable: '0' }
        tags: ownershipTags
        nodeLabels: { 'orka.ai/isolated-verification': 'true' }
      }
    ]
    networkProfile: {
      networkPlugin: 'azure'
      networkPluginMode: 'overlay'
      networkPolicy: 'cilium'
      networkDataplane: 'cilium'
      podCidr: podCidr
      serviceCidr: serviceCidr
      dnsServiceIP: cidrHost(serviceCidr, 10)
      loadBalancerSku: 'standard'
      outboundType: 'userAssignedNATGateway'
    }
    storageProfile: {
      diskCSIDriver: { enabled: true }
      fileCSIDriver: { enabled: false }
      snapshotController: { enabled: false }
    }
  }
  dependsOn: [
    networkAccess
  ]
}

resource builderNIC 'Microsoft.Network/networkInterfaces@2024-05-01' = {
  name: '${prefix}-builder'
  location: location
  tags: ownershipTags
  properties: {
    enableIPForwarding: false
    ipConfigurations: [
      {
        name: 'private'
        properties: {
          privateIPAllocationMethod: 'Static'
          privateIPAddress: builderPrivateIP
          subnet: { id: resourceId('Microsoft.Network/virtualNetworks/subnets', vnet.name, 'builder') }
        }
      }
    ]
  }
}

resource builder 'Microsoft.Compute/virtualMachines@2024-11-01' = {
  name: '${prefix}-builder'
  location: location
  tags: ownershipTags
  // No managed identity, extensions, customData, registry credentials, or kubeconfig.
  properties: {
    hardwareProfile: { vmSize: 'Standard_D4s_v5' }
    osProfile: {
      computerName: 'verification-builder'
      adminUsername: builderAdminUsername
      allowExtensionOperations: false
      linuxConfiguration: {
        disablePasswordAuthentication: true
        provisionVMAgent: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${builderAdminUsername}/.ssh/authorized_keys'
              keyData: operatorSshPublicKey
            }
          ]
        }
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: 'ubuntu-24_04-lts'
        sku: 'server'
        version: builderImageVersion
      }
      osDisk: {
        name: '${prefix}-builder-os'
        createOption: 'FromImage'
        diskSizeGB: 64
        deleteOption: 'Delete'
        managedDisk: { storageAccountType: 'StandardSSD_LRS' }
      }
      dataDisks: [
        {
          name: '${prefix}-builder-state'
          lun: 0
          createOption: 'Empty'
          diskSizeGB: 64
          deleteOption: 'Delete'
          managedDisk: { storageAccountType: 'StandardSSD_LRS' }
        }
      ]
    }
    networkProfile: {
      networkInterfaces: [{ id: builderNIC.id, properties: { deleteOption: 'Delete' } }]
    }
    diagnosticsProfile: { bootDiagnostics: { enabled: false } }
    securityProfile: {
      securityType: 'TrustedLaunch'
      uefiSettings: { secureBootEnabled: true, vTpmEnabled: true }
    }
  }
}

output clusterId string = cluster.id
output builderId string = builder.id
output vnetId string = vnet.id
output existingResourceIds array = [registry.id, egressIP.id, egress.id, nodeNSG.id, controlPlaneIdentity.id]
