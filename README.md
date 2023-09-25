# PSMSALNet Module

:warning: This is a **Powershel 7.2** module minimum but should work on Linux/MAC/Windows.

This project wraps [MSAL.NET](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet) functionality into PowerShell-friendly cmdlets. The goal is not to implement every flows MSAL can propose but the more useful and secured ones. Flow like ROPC or windows integrated flow won't be implemented for security reasons.

Why not using MSAL.PS module instead? MSAL.PS has not been updated since several months now and recently the module has been declared as an "archive" by Microsoft. On the other side, the MSAL.NET team did a wonderful job and has realeased a lot of neat features that won't be implemented in MSAL.PS.

Over the years, I've created a lot of identity scripts you can find in this Github account to interact with managed identities, Azure ARC for server or federated credentials. Rencently I've decided to create this module (mainly for my needs) because all those flows are now included in MSAL.NET which will simplify a lot of things :smiley:.

Thanks to MSAL.NET, I've discovered WAM (Web Account Manager) wich is a Windows feature compatible with modern authentication and more specificaly with MFA (compared to Windows Integrated flow)! The problem that I've discovered is that Powershell is not compatible with the library regarding WAM (at least I've stop after 20 hours of tries) this is why I've decided to try in C# directly. The funny thing is that I'm a newbie in C#.

Talking about libraries, this module rely a lot on various MSAL libraries:
- Microsoft.Identity.Client -> Core
- Microsoft.IdentityModel.Abstractions -> Core dependency
- Microsoft.Identity.Client.Broker > required for WAM
- Microsoft.Identity.Client.NativeInterop > required for WAM
- Microsoft.Identity.Client.Extensions.Msal > to serialize tokens on the local disks (in future version)

In addition, I created two other libraries for device code and WAM:
- [DeviceCodeHelper](https://github.com/SCOMnewbie/DeviceCodeHelper) -> Used for device code flow (no really?)
- [WAMHelper](https://github.com/SCOMnewbie/WAMHelper)

This module won't focus exclusively on the MSAL library but will add features around identity concepts in general to help us to better consume Entra features.

This module will feat perfectly with the [ValidateAADJWt](https://www.powershellgallery.com/packages/ValidateAADJwt) (maybe I should change the module name lol) to validate all tokens you will generate with this module.

## What you can do with this module?

### Generate Entra tokens with various flows (Get-EntraToken)

- Client credential flow with both secret and certificate for machine to machine communication (application context).
- Public Authorization Code with PKCE (human context).
- Device Code flow for headless Operating system. It's preferable to use the authorization code with PKCE instead (human context).
- Windows Account Manager flow (human context).
- On behalf flow (OBO) with both secret and certificate for your backend api (human context).
- System Managed identity from anywhere even Azure ARC for server (application context)!
- User Managed identity (application context).

To help you in this complex subject, this module will re-use ideas that I've implemented in other scripts. Several resources are pre-defined (Graph API, KeyVault, Storage, ARM...) to help you to find the proper resource. In addition, for user context only (application context is auto completed) you will have to define all the permissions you need. Check examples to better understand.

### Generate X509 certificate objects (ConvertTo-X509Certificate2, Get-KVCertificateWithPrivateKey, Get-KVCertificateWithPublicKey)

Using certificate in both Windows and Linux can become a pain quickly. This module will help you to exposed X509 certificate objects you will then consume with Get-EntraToken cmdlet. This function will propose several certifacte format/source:

- **Certificate Type**:
  - Pfx
  - Pem
  - Crt
  - Cer
- **Source**:
  - Local disk
  - Azure Keyvault (JWT token required)

## What will come next?

- Improve unit testing
- Improve documentation
- Implement local token serialization for public appilcations (flows that don't need secret/cert/assertion)

## How to use it

### Client credential flow

#### With secret

This command will generate a token and sotre it in memory (linked to the Pwsh process). MSAL will manage the expiration of the token and call Entra when it will be necessary.

```Powershell
$HashArguments = @{
  ClientId = "47077650-52a9-4bc2-b689-b50002b764ee"
  ClientSecret = $ClientSecret
  TenantId = $TenantId
  Resource = 'GraphAPI'
}
Get-EntraToken -ClientCredentialFlowWithSecret @HashArguments
```

If you want to force refresh, use instead:

```Powershell
$HashArguments = @{
  ClientId = "47077650-52a9-4bc2-b689-b50002b764ee"
  ClientSecret = $ClientSecret
  TenantId = $TenantId
  Resource = 'ARM'
  WithoutCaching = $true
}
Get-EntraToken -ClientCredentialFlowWithSecret @HashArguments
```

In this case, MSAL will generate a new token to access the Azure Resource Manager resource everytime.

#### With certificate

From a windows, we can do:

```Powershell
#https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-create-self-signed-certificate
$certname = "newcert"
$cert = New-SelfSignedCertificate -Subject "CN=$certname" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256
$mypwd = ConvertTo-SecureString -String "{myPassword}" -Force -AsPlainText
# This is what you keep
Export-PfxCertificate -Cert $cert -FilePath "C:\TEMP\$certname.pfx" -Password $mypwd
# This is what you will upload to Azure app registration
Export-Certificate -Cert $cert -FilePath "C:\TEMP\$certname.cer"
# Generate the X509 object
$X509 = ConvertTo-X509Certificate2 -PfxPath C:\TEMP\newcert.pfx -Password $(ConvertTo-SecureString -String '{myPassword}' -AsPlainText -Force) -Verbose

$HashArguments = @{
  ClientId = "47048650-52a9-4bc2-b689-b50002a764ee"
  ClientCertificate = $X509
  TenantId = $TenantId
  Resource = 'Keyvault'
  verbose = $true
}

Get-EntraToken -ClientCredentialFlowWithCertificate @HashArguments
```
This will generate a token but this time with a certificate instead of a secret. This is a more secure solution, you know you won't see certificate information in proxy/firewall/logs.
Always try to use certificate compared to secrets.

### Authorization code with PKCE

Imagine you want to access a resource protected by Entra and only selected person can access the resource. Because this is a public flow (in this case), no secret will be required because the user context itself is the "secret".

```Powershell

$HashArguments = @{
  ClientId = "4adbb0ff-3cde-4fc1-b22e-94ee7d16d70b"
  TenantId = $TenantId
  RedirectUri = 'http://localhost'
  Resource = 'GraphAPI'
  Permissions = @('user.read','group.read.all')
  ExtraScopesToConsent = @('https://management.azure.com/user_impersonation')
  verbose = $true
}

Get-EntraToken -PublicAuthorizationCodeFlow @HashArguments
```

Thanks to the ExtraScopesToConsent parameter, if you now type:

```Powershell

$HashArguments = @{
  ClientId = "4adbb0ff-3cde-4fc1-b22e-94ee7d16d70b"
  TenantId = $TenantId
  RedirectUri = 'http://localhost'
  Resource = 'ARM'
  Permissions = @('user_impersonation')
  verbose = $true
}

Get-EntraToken -PublicAuthorizationCodeFlow @HashArguments
```

You will hit the MSAL cache and won't have another windows for sign-in. To summarize, the first cmdlet requests a token to access Graph API with specific permissions and requests in parallel a token to access the Azure Resource Manager resource to avoid a second popup.

### Device code

Imagine now you're on WSL/Linux (headless Operating System) but you want to access a protected resource. This is where device code can be interesting.

:warning: This flow can be considered as less secure than the other flows. Don't forget to enabled the device code flow in your app registration and this flow won't be compatible with device compliant state.

```Powershell
Get-EntraToken -DeviceCodeFlow -ClientId $ClientId -TenantId $TenantId -Resource GraphAPI -Permissions @('user.read')
```

This command will use the default redirect uri which is 'http://localhost'.

## How to contribute

This module is based on Sampler module. To contribute, clone the repo and run a .\build.ps1 -Task build -ResolveDependency
