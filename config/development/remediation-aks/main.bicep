targetScope = 'subscription'

@description('Unique suffix for a NEW verification deployment. Existing resource groups must not be reused.')
@minLength(6)
@maxLength(12)
param suffix string

@allowed([
  'eastus2'
])
param location string = 'eastus2'

@minLength(1)
@maxLength(64)
param owner string

@description('Actual UTC start, set only AFTER an independently durable cleanup schedule is armed.')
param budgetStartUtc string

@description('Identifier of the reviewed, armed external cleanup receipt; never a credential.')
@minLength(1)
param cleanupReceipt string

@description('Reviewed source bundle digest, preserved from cleanup preparation.')
@minLength(64)
@maxLength(64)
param sourceDigest string

@description('Nonoverlapping RFC1918 /16; nodes use its first /22, the builder uses /27 number 128.')
param vnetCidr string

@description('Nonoverlapping overlay pod /16. Never route these addresses across clusters.')
param podCidr string

@description('Nonoverlapping Kubernetes Service /16.')
param serviceCidr string

@description('Trusted control-cluster NODE subnet, not overlay pod CIDRs; private peering requires separate approval.')
param trustedBuildClientCidr string

@description('Entire existing control VNet CIDR; new NSG rules deny other cross-VNet connections.')
param trustedControlVnetCidr string

@description('Pinned Canonical ubuntu-24_04-lts/server image version available in eastus2; never latest.')
param builderImageVersion string

@minLength(1)
@maxLength(32)
param builderAdminUsername string = 'buildoperator'

@description('Public SSH key only. No private key, password, kubeconfig, registry credential, or token.')
@secure()
param operatorSshPublicKey string

var prefix = 'orka-verify-${suffix}'
var ownershipTags = {
  'orka-purpose': 'isolated-remediation-verification'
  'orka-owner': owner
  'orka-deployment': prefix
  'orka-budget-start-utc': budgetStartUtc
  'orka-expires-at-utc': dateTimeAdd(budgetStartUtc, 'P1D')
  'orka-cleanup-receipt': cleanupReceipt
  'orka-source-digest': sourceDigest
}

resource verificationGroup 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: 'rg-${prefix}'
  location: location
  tags: ownershipTags
}

module foundation './resources.bicep' = {
  name: 'isolated-verification-foundation'
  scope: verificationGroup
  params: {
    prefix: prefix
    location: location
    ownershipTags: ownershipTags
    vnetCidr: vnetCidr
    podCidr: podCidr
    serviceCidr: serviceCidr
    trustedBuildClientCidr: trustedBuildClientCidr
    trustedControlVnetCidr: trustedControlVnetCidr
    builderImageVersion: builderImageVersion
    builderAdminUsername: builderAdminUsername
    operatorSshPublicKey: operatorSshPublicKey
  }
}

output verificationResourceGroupId string = verificationGroup.id
output managedNodeResourceGroupName string = 'rg-${prefix}-nodes'
output verificationClusterId string = foundation.outputs.clusterId
output builderVirtualMachineId string = foundation.outputs.builderId
output verificationVnetId string = foundation.outputs.vnetId
output verificationRegistryId string = foundation.outputs.registryId
output expiresAtUtc string = ownershipTags['orka-expires-at-utc']
