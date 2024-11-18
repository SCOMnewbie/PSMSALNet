# Changelog for PSMSALNet

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- N/A

## [0.1.1] - 2024-11-02 

### Added

- Bump MSAL version to 4.66.1 + all external dependencies
  
### Tested

#### Public Authorization Code Flow (PKCE)

[x] Get-EntraToken -PublicAuthorizationCodeFlow -ClientId $clientID -TenantId $TenantId -Resource GraphAPI -Permissions @("user.read") -Verbose
[x] Get-EntraToken -PublicAuthorizationCodeFlow -ClientId $clientID -TenantId $TenantId -Resource GraphAPI -Permissions @("user.read") -WithDebugLogging -Verbose
[x] Get-EntraToken -PublicAuthorizationCodeFlow -ClientId $clientID -TenantId $TenantId -Resource GraphAPI -Permissions @("user.read") -WithDebugLogging -WithLocalCaching -Verbose
[x] Get-EntraToken -PublicAuthorizationCodeFlow -ClientId $clientID -TenantId $TenantId -Resource GraphAPI -Permissions @("user.read") -WithDebugLogging -WithLocalCaching -TokenSerializationPath C:\TEMP -verbose
[x] Get-EntraToken -PublicAuthorizationCodeFlow -ClientId $clientID -TenantId $TenantId -Resource GraphAPI -Permissions @("user.read") -ExtraScopesToConsent @("api://PSMSALNet-backend/Access.AsUser")
[x]  Get-EntraToken -PublicAuthorizationCodeFlow -ClientId $clientID -TenantId $TenantId -Resource Custom -CustomResource "api://PSMSALNet-backend" -Permissions @("Access.AsUser")

#### Public Device Code Flow
[x] Get-EntraToken -DeviceCodeFlow -ClientId $ClientId -TenantId $TenantId -Resource GraphAPI -Permissions @("user.read")
[ ] Get-EntraToken -DeviceCodeFlow -ClientId $ClientId -TenantId $TenantId -Resource GraphAPI -Permissions @("user.read") -WithDebugLogging ->No logs provided

#### WAM Flow
[x] Get-EntraToken -WAMFlow -ClientId $ClientId -TenantId $TenantId -RedirectUri "ms-appx-web://Microsoft.AAD.BrokerPlugin/$clientId" -Resource GraphAPI -Permissions @("user.read")

#### OBO with secret
[x] Get-EntraToken -OnBehalfFlowWithSecret -ClientId '<backend clientId>' -ClientSecret '<backend secret>' -UserAssertion <token generated with client> -TenantId $tenantId -Resource GraphAPI -Permissions @("User.Read.All")

#### Client credential flow secret

[x] Get-EntraToken -ClientCredentialFlowWithSecret -ClientId $ClientId -ClientSecret $ClientSecret -TenantId $tenantId -Resource GraphAPI -WithDebugLogging

#### Client credential with certificate
$X509 = ConvertTo-X509Certificate2 -PfxPath C:\TEMP\testcertauth.pfx -Password $(ConvertTo-SecureString -String 'CertPassword' -AsPlainText -Force) -Verbose
[x] Get-EntraToken -ClientCredentialFlowWithCertificate -ClientId $ClientId -TenantId $TenantId -ClientCertificate $X509 -Resource GraphAPI -WithDebugLogging -Verbose

#### OBO with certificate
$X509 = ConvertTo-X509Certificate2 -PfxPath C:\TEMP\testcertauth.pfx -Password $(ConvertTo-SecureString -String 'CertPassword' -AsPlainText -Force) -Verbose
$t = Get-EntraToken -PublicAuthorizationCodeFlow -ClientId <Front ClientId> -TenantId $TenantId -Resource Custom -CustomResource api://PSMSALNet-backend -Permissions @("Access.AsUser") | % AccessToken
[x] Get-EntraToken -OnBehalfFlowWithCertificate -ClientId '<backend clientId>' -ClientCertificate $X509 -UserAssertion $t -TenantId $TenantId -Resource GraphAPI -Permissions @("User.Read.All")

#### Federated Flow (Not tested yet)

## [0.1.0] - 2024-05-15

### Added

- Added ConvertFrom-Jwt function
- Added ConvertFrom-Jwt tests

## [0.0.9] - 2024-05-10

### Added

- Bump in MSAL version (4.60.3) + all external dependencies
- Add Get-EntraToken more managed identity exemples into the functions
- Bump to net8.0 (Powershell 7.4)

### Fixed

-  Add FR language support in ConvertTo-X509Certificate2.Tests.ps1 to validate error message.

## [0.0.8] - 2023-10-24

### Added

- MSAL cache on filesystem available for public application (Auth code with PKCE, device code) to be resilient to console restart.
- Examples to use local MSAL token serialization.

### Fixed

- Clean useless code regarding client credential flow.

## [0.0.7] - 2023-10-16

### Fixed

- Following Azure [ARC for Linux issue confirmed by the MSAL.Net team](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/issues/4358), a temporary fix is provided until the day MSAL.Net will include this feature. This flow, only generate an access token and doesn't use the MSAL memory cache.
 
## [0.0.6] - 2023-10-13

### Fixed

- FederatedCredentialFlowWithAssertion was broken with message 'AADSTS50027: JWT token is invalid or malformed', MSAL is waiting for a string directly instead of a userassignment object.

### Added

- Documentation about FederatedCredentialFlowWithAssertion parameter and a real Kubernetes example under Examples\aks-workloadidentity
- README is updated for FederatedCredentialFlowWithAssertion parameter
- Add new FederatedCredentialFlowWithAssertion flow example in the Get-Entra cmdlet

## [0.0.5] - 2023-10-06

### Added

- Add MSAL logging with the WithDebugLogging parameter
- Add PSMSALNetHelper.dll library

## [0.0.4] - 2023-09-27

### Added

- Add new WAM flow example in the Get-Entra cmdlet
- Add new WAM flow example in the README
- Add new OBO flow examples (secret + certificate) in README
- Add new OBO flow example in the Get-Entra cmdlet
- Add a lot of system managed identity examples
- Project URL in powershell gallery

## [0.0.3] - 2023-09-25

### Fixed

- The private cmdlet exposed by the WAMHelper.dll which is required for the -WAMflow parameter wasn't loaded into the module through the RequiredAssemblies into the psd1 file. The module is now manually added to the psm1 file with the prefix.ps1 script and the build.yml parameter file.

## [0.0.2] - 2023-09-25

### Added

- Add new client credential flow example in the Get-Entra cmdlet
- Add new client credential flow example in the README
- Add new authorization code flow example in the Get-Entra cmdlet
- Add new authorization code flow example in the README
- Add new device code flow example in the Get-Entra cmdlet
- Add new device code flow example in the README

### Changed

- Get-EntraToken -ClientCredentialFlowWithSecret output a non necessary line in the output. Remove it.
- Get-EntraToken -PublicAuthorizationCodeFlow output a non necessary line in the output. Remove it.
- Added new WAMHelper version without dotnet framwork requirement.

### Removed

- N/A

## [0.0.1] - 2023-09-23

### Added

- This is the initial version

### Changed

- N/A

### Removed

- N/A
