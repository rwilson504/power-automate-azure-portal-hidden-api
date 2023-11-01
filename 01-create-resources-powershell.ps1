<#
    .SYNOPSIS
    This script can be used to create an invironment to store refresh token into an Azure Key Vault. The script creates a resource group and a Key Vault.

    This script is without warranty and not for commercial use without prior consent from the author. It is meant for scenario's where you need an Azure token to automate something that cannot yet be done with service principals.
 
    .EXAMPLE
    .\01-create-hidden-api-environment.ps1 -Location "eastus" -ResourceGroupName "hidden-resourcegroup" -KeyVaultName "hidden-kv" -WorkflowName "hidden-workflow" -TenantId "123e4567-e89b-12d3-a456-426614174000" -SubscriptionId "123e4567-e89b-12d3-a456-426614174001"
    
    .PARAMETER Location
    The resource's location
    
    .PARAMETER ResourceGroupName
    The resource group to create
    
    .PARAMETER KeyVaultName
    The key vault name to create    
    
    .PARAMETER TenantId
    The tenant id to use for the Azure login
    
    .PARAMETER SubscriptionId
    The subscription id to use for the Azure login 
    
    .PARAMETER Environment
    The Azure environment to use for the Azure login. Can be either "AzureCloud" or "AzureUSGovernment". Default is "AzureCloud".
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]$Location = "eastus",
    [parameter()]
    [string]$ResourceGroupName = "hidden_api",
    [parameter()]
    [string]$KeyVaultName= "HiddenAPIKeyVault",
    [parameter()]
    [string]$TenantId,
    [parameter()]
    [string]$SubscriptionId,
    [Parameter( Mandatory = $false)]
    [ValidateSet("AzureCloud", "AzureUSGovernment")]
    [string]$Environment = "AzureCloud"       
)

<#
.DESCRIPTION 
 Connect to Azure with device authentication using the management url so that it can interact with Azure resources such as Key Vault, Logic Apps and Resource Groups.
#>
Connect-AzAccount -Tenant $TenantId -Subscription $SubscriptionId -UseDeviceAuthentication -Environment $Environment

$AzureMangementUrl = if ($Environment -eq "AzureUSGovernment") {"https://management.usgovcloudapi.net"} else {"https://management.azure.com"}

$method = "PUT"
try {
    $context = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
    $token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $AzureMangementUrl).AccessToken
    $headers = @{
        'Content-Type' = 'application/json'
        Authorization  = 'Bearer ' + $token
    }
    #$tenantId = $context.Tenant.Id
    $subscriptionId = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext.Subscription.Id
}
catch {
    Write-Output "Failed to find context. use Connect-AzAccount to login"   
}

<#
.DESCRIPTION 
 Create the resource group first, if its not there allready.
#>
try {    
    $rgUri = "{0}/subscriptions/{1}/resourcegroups/{2}?api-version=2021-04-01" -f $AzureMangementUrl, $subscriptionId, $resourceGroupName
    $rgBody = @{
        location = $location
    } | ConvertTo-Json -Depth 5
    $rgParameters = @{
        uri     = $rgUri
        method  = $method
        headers = $headers
        body    = $rgBody
    }
    $rg = Invoke-RestMethod @rgParameters
    $rg
}
catch {
    Write-Output "Failed to create resource group $ResourceGroupName, $_"   
}

<#
.DESCRIPTION 
Create Key Vault
.NOTES 
TODO: Move this code after the Logic App creation, so that the logic app connector outgoing IP addresses can be added to the key vault and the public network access restricted to just those IPs.
#>
try {
    $uri = "{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.KeyVault/vaults/{3}?api-version=2021-10-01" -f $AzureMangementUrl, $subscriptionId, $resourceGroupName, $KeyVaultName
    $kvBody = @{
        location   = $Location
        properties = @{
            enablePurgeProtection   = $true
            enableRbacAuthorization = $true
            publicNetworkAccess     = "Enabled"
            tenantId                = $TenantId
            sku                     = @{
                family = "A"
                name   = "standard"
            }
        }
    } | ConvertTo-Json -Depth 5

    $keyVaultParameters = @{
        uri     = $uri
        method  = $method
        headers = $headers
        body    = $kvBody
    }
    $kv = Invoke-RestMethod @keyVaultParameters
    $kv
}
catch {
    Write-Output "Failed to create key vault $KeyVaultName, $_"   
}