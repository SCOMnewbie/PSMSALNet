# Changelog for PSMSALNet

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Bump in MSAL version

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
