# Changelog for PSMSALNet

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add new WAM flow example in the Get-Entra cmdlet
- Add new WAM flow example in the README

### Fixed

- N/A

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
