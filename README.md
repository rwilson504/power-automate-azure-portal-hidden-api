![Power Automate Blueprint Accessing Azure Portal Backend APIs and the Intricacies of main.iam.ad.ext.azure.com](https://github.com/rwilson504/power-automate-azure-portal-hidden-api/assets/7444929/6f67a1f1-2456-48d0-8638-93fa3cabb301)

In the realms of digital infrastructure management, automation emerges as a pivotal ally, especially when confronting repetitive and time-sensitive tasks. A recent endeavor led me to a scenario where automating the management of OAuth tokens for users within our organization was paramount. Our meticulous record-keeping of these tokens and their respective assignments is handled through Power Apps. However, the manual aspect of adding these tokens via the Azure portal, which necessitated the upload of a CSV file each time, posed a cumbersome challenge.

Given the current preview status of this functionality, a straightforward method through Graph API was conspicuously absent. Thus, I aimed to devise an automated framework, enabling individuals with the appropriate permissions in Power Apps to seamlessly add these tokens for users. While this wouldn't entirely absolve admins of their duties—they would still need to activate the tokens within the Azure portal—it significantly mitigated the manual labor involved in creating and uploading the CSV file.

My exploration revealed that during a manual CSV file upload, an API located at main.iam.ad.ext.azure.com is triggered in the background. However, this API is a closed door, accessible exclusively via the Azure portal and not through an app registration. This discovery beckoned a deeper dive to harness this API for automating the OAuth token management chore.

This trail led to the crafting of a solution using Power Automate, which is the focal point of this article. The scripts and methodologies delineated here draw inspiration and foundational knowledge from the following insightful articles:

- [Utilizing the internal main.iam.ad.ext.azure.com API with Logic Apps](https://rozemuller.com/use-internal-azure-api-with-logic-apps/)
- [Employing the internal main.iam.ad.ext.azure.com API in automation](https://rozemuller.com/use-internal-azure-api-in-automation/#authenticate-to-mainiamadextazurecom)
- [Accessing the backend Azure AD APIs behind portal.azure.com](https://goodworkaround.com/2020/11/27/accessing-the-backend-azure-ad-apis-behind-portal-azure-com/)

While these articles unveiled a treasure trove of information, I envisioned extending this knowledge by showcasing how this automation could be embodied within Power Automate. This article, therefore, aspires to bridge that informational chasm and furnish a step-by-step guide on configuring the main.iam.ad.ext.azure.com API with Power Automate to automate OAuth token management, albeit it’s crucial to note that main.iam.ad.ext.azure.com is an unsupported API, which calls for a cautious approach in a production environment.

## Service Account

Utilizing the main.iam.ad.ext.azure.com API requires a distinct approach for authentication due to its unsupported status and exclusive accessibility via the Azure portal. Unlike many Azure services, this API doesn’t support service principal access, which is a common method for non-interactive, automated access within Azure environments.

To navigate this, it's advisable to create a dedicated service account with the precise permissions required to interact with the main.iam.ad.ext.azure.com API. This setup aligns with the principle of least privilege (PoLP), ensuring the account has only the necessary access rights, and facilitates easier auditing and monitoring of the automated processes.

Creating a service account is a good practice from a security standpoint. It not only provides a workaround for the lack of service principal support but also ensures that all actions carried out by the automation processes are traceable, thus enhancing the security and accountability of the setup.

**Important Note on MFA and Token Lifetime:** If your Azure environment has Multi-factor authentication (MFA) requirements set up through conditional access, it can affect the token lifetime for the service account. In scenarios where this becomes a hindrance to automation processes, you may need to consider excluding or adjusting the MFA requirements for the service account. However, always ensure that any changes made align with your organization's security policies and best practices.

## Initial Key Vault Setup

Azure Key Vault is a pivotal component in this setup, acting as a secure repository for storing and managing the refresh token needed for automation. It provides a centralized platform to safeguard sensitive data such as secrets, encryption keys, and certificates.

### Resource Provider Registration

Before diving into scripts or deployment files, ensure that the necessary Azure resource providers are registered within your subscription, particularly Microsoft.Authorization and Microsoft.KeyVault. These providers are crucial for creating and managing the Key Vault and setting the necessary permissions.

![image](https://github.com/rwilson504/power-automate-azure-portal-hidden-api/assets/7444929/3a9826cb-ecd9-42f8-91d2-df47a48ba54f)

### Deployment Options

There are various avenues to set up the Key Vault – you can employ Azure PowerShell, Azure CLI, or Bicep files, among other methods. In this guide, both PowerShell scripts and Bicep files are provided to offer flexibility based on your preferences or environment constraints.

#### PowerShell Scripts

A script named [01-create-resources-powershell.ps1](https://github.com/rwilson504/power-automate-azure-portal-hidden-api/raw/main/power-platform-solutions/01-create-resources-powershell.ps1) is provided to facilitate the creation of a resource group and a Key Vault. It's an executable script where you just need to replace the parameters with your environment details.

```*.sh-session
.\01-create-hidden-api-environment.ps1 -Location "eastus" -ResourceGroupName "hidden-resourcegroup" -KeyVaultName "hidden-kv" -TenantId "123e4567-e89b-12d3-a456-426614174000" -SubscriptionId "123e4567-e89b-12d3-a456-426614174001"
```

#### Bicep Files

Bicep is a declarative language for describing and deploying Azure resources. It simplifies the process of writing and managing Azure Resource Manager (ARM) templates. Bicep files offer a streamlined method to deploy resources directly from Visual Studio Code, provided you have the Bicep extension installed. The files included in this guide are structured to deploy a resource group and a Key Vault effortlessly.

What is great about these files is that you can easily deploy from within Visual Studio Code.  Just install the Bicep extension.

![image](https://github.com/rwilson504/power-automate-azure-portal-hidden-api/assets/7444929/dbbbe922-8346-4756-94ab-49d5be154186)

Then right click on the bicep file to deploy.  The main.parameters.json file can be used to supply all the necessary parameters for deployment.

![image](https://github.com/rwilson504/power-automate-azure-portal-hidden-api/assets/7444929/be99a9fc-c4c7-4fc9-91fc-c78827e521ff)

Both deployment methods are designed to abstract the complexities involved in setting up Azure Key Vault, providing a straightforward path to secure the refresh token necessary for automation.

#### Azure Portal

- Navigate to the Azure portal, then select "Create a resource."
- In the "Search the Marketplace" field, type "Key Vault" and select it from the list.
- Click the "Create" button to open the "Create Key Vault" blade.
- Fill in the necessary fields such as the Name, Subscription, Resource Group, and Location.
- Review the other settings and adjust them according to your preferences or requirements.
- Click the "Review + create" button, review your settings one final time, and then click "Create" to deploy the Key Vault.

## Acquiring the Initial Refresh Token

For the automation to function seamlessly, acquiring a refresh token initially is crucial. This token will serve as the bridge for obtaining new access tokens, allowing the automation to interact with the main.iam.ad.ext.azure.com API securely.

A PowerShell script named [02-set-initial-refresh-token.ps1](https://github.com/rwilson504/power-automate-azure-portal-hidden-api/raw/main/power-platform-solutions/02-set-initial-refresh-token.ps1) is provided to facilitate this process. When executed, this script will prompt you to sign in twice. The first login should be performed with an account that possesses the requisite permissions to update the Key Vault. Following this, a second login prompt will appear. This is where you would log in using the service account created earlier, which has been configured with just the necessary rights to interact with the Azure API. This dual-login mechanism ensures that the process is securely handled, aligning with the principle of least privilege while setting the stage for automated interactions with the main.iam.ad.ext.azure.com API. The example below shows you how to run the script, replace the parameters with your environment details.

```*.sh-session
.\02-set-initial-refresh-token.ps1 -TenantId "123e4567-e89b-12d3-a456-426614174000" -SubscriptionId "123e4567-e89b-12d3-a456-426614174001" -KeyVaultName "hidden-kv"
```

## Automation Framework Setup

Embarking on the automation of OAuth token management necessitates a structured setup within Power Automate and Azure. The steps below delineate the essential configurations:

### Create App Registration

- There's no need to add any API roles.
- Generate a new secret, copying the secret value for safekeeping, as it will be crucial when creating the connection for Key Vault in Power Automate.
- Ensure to also copy the Application (Client) ID and the Directory (tenant) ID, which will be required for the connection within Power Automate.
  
![image](https://github.com/rwilson504/power-automate-azure-portal-hidden-api/assets/7444929/56a79799-527e-41ff-8396-98ed6e1f084f)

### Install the Azure Key Vault Custom Connectors
  
Either install the Azure Key Vault custom connectors solution [AzurePortalAPICustomConnector_1_0_0_2](https://github.com/rwilson504/power-automate-azure-portal-hidden-api/raw/main/power-platform-solutions/AzurePortalAPICustomConnector_1_0_0_2.zip), or follow the installation guidelines provided [here](https://github.com/Microsoft/PowerPlatformConnectors/tree/master/custom-connectors/AzureKeyVault). Utilizing a custom connector is vital since the certified connector for Key Vault doesn’t allow writing secrets back to the Key Vault, a feature requisite for this solution.
- Update the host URL to reflect your new Key Vault.

![image](https://github.com/rwilson504/power-automate-azure-portal-hidden-api/assets/7444929/e6291654-ecc1-4915-b729-95c8f6b0e3d6)

- Revise the security section:
- Ensure the Enable Service Principal support option is selected.
- Input the details copied from the app registration you created.
  - For the authentication URL, use:
    - Azure Cloud: `https://login.microsoftonline.com`
    - Azure Government: `https://login.microsoftonline.us`
  - For the Resource URL use:
    - Azure Cloud: `https://vault.azure.net`
    - Azure Government: `https://vault.usgovcloudapi.net`

![image](https://github.com/rwilson504/power-automate-azure-portal-hidden-api/assets/7444929/3a05e59e-d23e-40f5-8cad-bfbae5a11f60)

- Copy the Redirect URL from the security section, to be added within the app registration later.

![image](https://github.com/rwilson504/power-automate-azure-portal-hidden-api/assets/7444929/0dd6016d-b327-408e-8133-f67648bc4ce4)

### Update App Registration

Incorporate the Power Automate redirect URL into the app registration.

![image](https://github.com/rwilson504/power-automate-azure-portal-hidden-api/assets/7444929/d060a313-94b5-4cc1-994f-dce807295d1b)

### Key Vault Access Management

Designate the app registration as a Key Vault Secrets Officer in Key Vault, ensuring the requisite permissions for reading and writing secrets are granted.

![image](https://github.com/rwilson504/power-automate-azure-portal-hidden-api/assets/7444929/537e6ab1-3a38-4642-a883-f0868d35c17d)

## Power Automate Flow

The culmination of our setup is the creation of a Power Automate flow, designed to automate the process of managing OAuth tokens. Initially, the flow retrieves the existing refresh token from Key Vault, utilizes it to log in the service account, and upon a successful login, acquires a new refresh token alongside an access token. The new refresh token is then stored back in Key Vault, extending its lifespan, while the access token is employed to interact with the `main.iam.ad.ext.azure.com` API.

For a hands-on experience, you can download a solution containing the sample Flow from here: [AzurePortalAPIFlowExample_1_0_0_4.zip](https://github.com/rwilson504/power-automate-azure-portal-hidden-api/raw/main/power-platform-solutions/AzurePortalAPIFlowExample_1_0_0_4.zip).

**Important Note:** Ensure to secure all input and output parameters within any actions that may utilize the refresh token or access token to safeguard against unauthorized access.

![image](https://github.com/rwilson504/power-automate-azure-portal-hidden-api/assets/7444929/d35adbdc-446b-416a-a609-2d5472efef6a)

### Get Refresh Token

The journey begins with the 'Get secret' action, courtesy of our custom KeyVault connector, fetching the refresh token from Key Vault to set the stage for the login process.

![image](https://github.com/rwilson504/power-automate-azure-portal-hidden-api/assets/7444929/7994e384-b765-434c-9358-9e10810219c7)

Upon adding this action to your flow, select `Service Principal Connection` as the authentication type, and furnish the details from the app registration created earlier.

![image](https://github.com/rwilson504/power-automate-azure-portal-hidden-api/assets/7444929/6c09cffc-f8f3-467c-a4e7-2434c7a8c232)

### Parse JSON from Refresh Token

Simplify the subsequent steps by parsing the KeyVault response using the 'Parse JSON' action.

![image](https://github.com/rwilson504/power-automate-azure-portal-hidden-api/assets/7444929/37600217-adf0-401f-b272-63eb9ebdabc6)

The following schema can be copy/pasted into this action.

```json
{
    "properties": {
        "attributes": {
            "properties": {
                "created": {
                    "type": "integer"
                },
                "enabled": {
                    "type": "boolean"
                },
                "recoverableDays": {
                    "type": "integer"
                },
                "recoveryLevel": {
                    "type": "string"
                },
                "updated": {
                    "type": "integer"
                }
            },
            "type": "object"
        },
        "id": {
            "type": "string"
        },
        "value": {
            "type": "string"
        }
    },
    "type": "object"
}
```

### Login

The 'HTTP' action propels a POST request to the AD OAuth token endpoint to procure the authorization token essential for Azure API interactions.

![image](https://github.com/rwilson504/power-automate-azure-portal-hidden-api/assets/7444929/fa7a43fe-4ea2-48b3-87ee-f900e0830ea1)

URI (Replace {tenant-id} with your own tenant Id):
- Azure Cloud: `https://login.windows.net/{tenant-id}/oauth2/token`
- Azure Government: `https://login.microsoftonline.us/{tenant-id}/oauth2/token`
  
Header:

`content-type`:`application/x-www-form-urlencoded`

Body:
  -Azure Cloud:

  ```*.txt
  resource=74658136-14ec-4630-ad9b-26e160ff0fc6&grant_type=refresh_token&refresh_token=@{body('Parse_JSON_From_Refresh_Token')?['value']}&client_id=1950a258-227b-4e31-a9cf-717495945fc2&scope=openid
  ```

  -Azure Government:

  ```*.txt
  resource=ee62de39-b9b0-4886-aa58-08b89c4e3db3&grant_type=refresh_token&refresh_token=@{body('Parse_JSON_From_Refresh_Token')?['value']}&client_id=1950a258-227b-4e31-a9cf-717495945fc2&scope=openid
  ```

### Parse JSON from Login

Dive into the login response to extract the access and refresh tokens using the 'Parse JSON' action.

![image](https://github.com/rwilson504/power-automate-azure-portal-hidden-api/assets/7444929/1cf15732-a132-4b80-8980-f1737ee4719d)

Utilize this schema:

```json
{
  "properties": {
      "access_token": {
          "type": "string"
      },
      "expires_in": {
          "type": "string"
      },
      "expires_on": {
          "type": "string"
      },
      "ext_expires_in": {
          "type": "string"
      },
      "foci": {
          "type": "string"
      },
      "id_token": {
          "type": "string"
      },
      "not_before": {
          "type": "string"
      },
      "refresh_token": {
          "type": "string"
      },
      "resource": {
          "type": "string"
      },
      "scope": {
          "type": "string"
      },
      "token_type": {
          "type": "string"
      }
  },
  "type": "object"
}
```

### Set new Refresh Token

With a new refresh token at hand, update Key Vault using the 'Create or update secret value' action via the AzureKeyVault custom connector, thereby elongating the token's lifespan.

![image](https://github.com/rwilson504/power-automate-azure-portal-hidden-api/assets/7444929/aad5bb7d-c6a2-4ffa-8d5b-b8b6d743c4a3)

### HTTP to Azure API

The curtain call involves employing the access token, obtained from the Login action, to interact with the Azure API. In this illustration, we’re fetching the account SKUs.

![image](https://github.com/rwilson504/power-automate-azure-portal-hidden-api/assets/7444929/ec34d95a-8a36-4555-aab7-5ecb8c0dd1ab)

## Upload Auth Token

The primary incentive behind devising this solution was to automate the simulation of uploading a hardware token CSV. The subsequent details exhibit the URLs and a sample body JSON for this purpose:

To delve deeper into the realm of OATH tokens in Azure Entra, explore the following link: [Authentication methods in Microsoft Entra ID - OATH tokens](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-oath-tokens).

### Sample URL/Payload

**Commercial URLs:**

- Azure Cloud: `https://main.iam.ad.ext.azure.com/api/MultifactorAuthentication/HardwareToken/upload`
- Azure Government: `https://main.iam.ad.ext.azure.us/api/MultifactorAuthentication/HardwareToken/upload`

**Body:**

```json
{
  "content": "upn,serial number,secret key,time interval,manufacturer,model\r\ntest@mydomain.com,1234567,2234567abcdef2234567abcdef,30,Contoso,HardwareKey",
  "id": null,
  "mimeType": "application/vnd.ms-excel",
  "name": "760b21fc-128a-4504-9374-71f47638e27c.csv"
}
```

In the final HTTP action of the Power Automate Flow, the above URLs and body can be employed to automate the hardware token upload process. You would specify the corresponding URL (based on your Azure environment) in the HTTP action's URI field, and the provided JSON payload in the Body field. This automation step is crucial as it streamlines the hardware token management process by allowing a seamless upload of token data through the main.iam.ad.ext.azure.com API.

The payload above delineates the necessary information for uploading hardware tokens, embodying user details, token attributes, and the corresponding hardware specifics.

In conclusion, leveraging the main.iam.ad.ext.azure.com API in conjunction with Power Automate facilitates a seamless automation of hardware token management, thereby significantly reducing manual labor and enhancing security by minimizing human error.
