targetScope = 'resourceGroup'

param zoneName string
param controlVnetId string
param ownershipTags object

resource zone 'Microsoft.Network/privateDnsZones@2024-06-01' existing = {
  name: zoneName
}

resource link 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: zone
  name: 'to-control'
  location: 'global'
  tags: ownershipTags
  properties: {
    virtualNetwork: { id: controlVnetId }
    registrationEnabled: false
  }
}
