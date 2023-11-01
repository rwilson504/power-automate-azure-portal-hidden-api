<#
    .SYNOPSIS 
    This script is used after keyvault and the workflow are created. It's primary function is
    to store the refresh token in the keyvault. This would need to be done before the initial run of the
    workflow or if the refresh token were to ever expire due to inactvity.

    This scipt is without warranty and not for commercial use without prior consent from the author. 
    It is meant for scenario's where you need an Azure token to automate something that cannot yet be 
    done with service principals.

    .EXAMPLE
    .\02-set-initial-refresh-token.ps1 -TenantId "123e4567-e89b-12d3-a456-426614174000" -SubscriptionId "123e4567-e89b-12d3-a456-426614174001" -KeyVaultName "hidden-kv"
    
    .PARAMETER KeyVaultName
    The name of the Key Vault where the refresh token will be stored.

    .PARAMETER KeyVaultSecretName
    The name of the secret in the Key Vault where the refresh token will be stored. Default is "RefreshToken".

    .PARAMETER TenantId
    The tenant id to use for the Azure login.

    .PARAMETER SubscriptionId
    The subscription id to use for the Azure login.

    .PARAMETER Environment
    The Azure environment to use for the Azure login. Can be either "AzureCloud" or "AzureUSGovernment". Default is "AzureCloud".

    .PARAMETER RefreshToken
    The refresh token to be stored in the Key Vault. This token is used to authenticate with Azure AD and obtain access tokens for API calls.
    If this parameter is not supplied, the script will attempt to use a cached refresh token from the current user's profile. If no cached
    refresh token is found, the script will attempt to perform an interactive login to obtain a refresh token. If the script is not run interactively
    and no refresh token is supplied, the script will fail.     

    .NOTES
    Make sure the inital acocunt used for login has the Key Vault Secret Officer role on the Key Vault before running this script.
#>

[CmdletBinding()]
Param(
    [Parameter()]
    [string]$KeyVaultName,
    [Parameter()]
    [string]$KeyVaultSecretName = "RefreshToken",    
    [Parameter()]
    [string]$TenantId,
    [Parameter()]
    [string]$SubscriptionId,
    [Parameter( Mandatory = $false)]
    [ValidateSet("AzureCloud", "AzureUSGovernment")]
    [string]$Environment = "AzureCloud",
    [Parameter( Mandatory = $false)]
    [string]$RefreshToken
)

Write-Host "Please log in to the Key Vault. This login will be used exclusively for setting the Key Vault secret. Ensure that this account has the 'Key Vault Secret Officer' role assigned to it for the Key Vault.`n" -ForegroundColor Green
Connect-AzAccount -Tenant $TenantId -Subscription $SubscriptionId -UseDeviceAuthentication -Environment $Environment | Out-Null

# Set variables based on Azure environment
$resource = if ($Environment -eq "AzureUSGovernment") {"main.iam.ad.ext.azure.us"} else {"main.iam.ad.ext.azure.com"}
$HiddenAPIAppId = if($Environment -eq "AzureUSGovernment"){"ee62de39-b9b0-4886-aa58-08b89c4e3db3"} else {"74658136-14ec-4630-ad9b-26e160ff0fc6"}
$ADLoginUrl = if ($Environment -eq "AzureUSGovernment") {"https://login.microsoftonline.us"} else {"https://login.microsoftonline.com"}
$clientId = "1950a258-227b-4e31-a9cf-717495945fc2"

if ($RefreshToken) {
    try {
        write-verbose "checking provided refresh token and updating it"
        $response = (Invoke-RestMethod "$ADLoginUrl/$tenantId/oauth2/token" -Method POST -Body "grant_type=refresh_token&refresh_token=$RefreshToken" -ErrorAction Stop)
        $RefreshToken = $response.refresh_token
        write-verbose "refresh and access token updated"
    }
    catch {
        Write-Output "Failed to use cached refresh token, need interactive login or token from cache"   
        $RefreshToken = $False 
    }
}

if ($KeyVaultName -and $RefreshToken) {
    try {
        write-verbose "getting refresh token from cache"
        $RefreshToken = Get-Content $RefreshTokenCachePath -ErrorAction Stop | ConvertTo-SecureString -ErrorAction Stop
        $RefreshToken = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($RefreshToken)
        $RefreshToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($RefreshToken)
        $response = (Invoke-RestMethod "$ADLoginUrl/$tenantId/oauth2/token" -Method POST -Body "grant_type=refresh_token&refresh_token=$RefreshToken" -ErrorAction Stop)
        $RefreshToken = $response.refresh_token
        write-verbose "tokens updated using cached token"
    }
    catch {
        Write-Output "Failed to use cached refresh token, need interactive login"
        $RefreshToken = $False
    }
}

if (!$RefreshToken) {
    Write-Verbose "No cache file exists and no refresh token supplied, we have to perform interactive logon"
    Write-Host "`n`nPlease log in with the account that will be used to access the 'main.iam.ad.ext.azure' API. Ensure that this account has only the necessary permissions required for the automation tasks you intend to perform.`n" -ForegroundColor Green    
    if ([Environment]::UserInteractive) {
        foreach ($arg in [Environment]::GetCommandLineArgs()) {
            if ($arg -like '-NonI*') {
                Throw "Interactive login required, but script is not running interactively. Run once interactively or supply a refresh token with -refreshToken"
            }
        }
    }

    try {
        Write-Verbose "Attempting device sign in method"
        $response = Invoke-RestMethod -Method POST -UseBasicParsing -Uri "$ADLoginUrl/$TenantId/oauth2/devicecode" -ContentType "application/x-www-form-urlencoded" -Body "resource=https%3A%2F%2F$resource&client_id=$clientId"
        Write-Output $response.message
        $waited = 0
        while ($true) {
            try {
                $authResponse = Invoke-RestMethod -uri "$ADLoginUrl/$TenantId/oauth2/token" -ContentType "application/x-www-form-urlencoded" -Method POST -Body "grant_type=device_code&resource=https%3A%2F%2F$resource&code=$($response.device_code)&client_id=$clientId" -ErrorAction Stop
                $RefreshToken = $authResponse.refresh_token
                break
            }
            catch {
                if ($waited -gt 300) {
                    Write-Verbose "No valid login detected within 5 minutes"
                    Throw
                }
                #try again
                Start-Sleep -s 5
                $waited += 5
            }
        }
    }
    catch {
        Throw "Interactive login failed, cannot continue"
    }
}

if ($KeyVaultName -and $RefreshToken) {
    write-verbose "caching refresh token"
    try {
        $secretvalue = ConvertTo-SecureString $RefreshToken -AsPlainText -Force
        Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $KeyVaultSecretName -SecretValue $secretvalue
        Write-Output "Refresh token stored in Key Vault"
    }
    catch {
        Write-Output "Not able to write secret to Key Vault"
    }
}
else {
    Throw "No refresh token found in cache and no valid refresh token passed or received after login, cannot continue"
}

try {
    write-verbose "update token for supplied resource"
    $response = (Invoke-RestMethod "$ADLoginUrl/$TenantId/oauth2/token" -Method POST -Body "resource=$HiddenAPIAppId&grant_type=refresh_token&refresh_token=$RefreshToken&client_id=$clientId&scope=openid" -ErrorAction Stop)
    $resourceToken = $response.access_token
    write-verbose "token translated to $resource"
}
catch {
    Throw "Failed to translate access token to $resource , cannot continue"
}