targetScope='subscription'

param location string
param resourceGroupName string
param keyVaultName string

resource rg 'Microsoft.Resources/resourceGroups@2021-04-01' = {
  name: resourceGroupName
  location: location
}

module kv './keyvault.bicep' = {
  name: keyVaultName
  scope: rg
  params:{
    keyVaultName: keyVaultName
    location: location
  }
}
