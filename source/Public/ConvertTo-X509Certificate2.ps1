<#
.SYNOPSIS
This function will output a X509Certificate2 certificate.
.DESCRIPTION
Because Linux does not have the Cert: provider (Get-PsProvider), we have to find a way to use the provided certificate on all platforms and X509
is a solution. This function will inject several format (cer,crt,pem,pfx) to expose the result in a standardized way.
.PARAMETER PfxPath
Specify path of a pfx file.
.PARAMETER PemPath
Specify path of a pem file.
.PARAMETER CerPath
Specify path of a cer file.
.PARAMETER CrtPath
Specify path of a crt file.
.PARAMETER Password
Specify password of a pfx file.
.PARAMETER PrivateKeyPath
Specify path of a decrypted private key.
.PARAMETER KeyVaultCertificatePath
Specify path of a specific certificate version hosted on Azure Key Vault.
.PARAMETER AccessToken
Specify an access token to contact the associated Key Vault.
.PARAMETER APIVersion
Specify the API version regarding Keyvault API for now the default value is 7.3.
.PARAMETER ExportPrivateKey
Specify you want to extract from Key Vault the certificate with the Private key.
.EXAMPLE

$PubCert = ConvertTo-X509Certificate2 -CerPath ./scomnewbie.cer

Will generate a X509Certificate2 without private key from a cer file.

.EXAMPLE

$PubCert = ConvertTo-X509Certificate2 -CerPath ./scomnewbie.crt

Will generate a X509Certificate2 without private key from a crt file.

.EXAMPLE

$PrivCert = ConvertTo-X509Certificate2 -PfxPath ./scomnewbie.pfx -Password $(ConvertTo-SecureString -String "exportpassword" -AsPlainText -Force)
$PrivCert.PrivateKey

Will generate a X509Certificate2 with private key from a pfx file.

.EXAMPLE

$PrivCert = ConvertTo-X509Certificate2 -PemPath ./scomnewbie2.pem -PrivateKeyPath ./privatekey_rsa.key
$PrivCert.PrivateKey

Will generate a X509Certificate2 with private key from a pem file.

.EXAMPLE

$CertURL = 'https://<myvault>.vault.azure.net/certificates/test/5d69153b75214245ab72fa21b9c06bfb'
$KVToken = (Get-AzAccessToken -Resource "https://vault.azure.net").Token #Once authenticated to Azure
ConvertTo-X509Certificate2 -KeyVaultCertificatePath $CertURL -AccessToken $KVToken

Will generate a X509Certificate2 with public key from a certificate hosted in Key Vault.
.EXAMPLE

$CertURL = 'https://<myvault>.vault.azure.net/certificates/test/5d69153b75214245ab72fa21b9c06bfb'
$KVToken = (Get-AzAccessToken -Resource "https://vault.azure.net").Token #Once authenticated to Azure
ConvertTo-X509Certificate2 -KeyVaultCertificatePath $CertURL -AccessToken $KVToken -ExportPrivateKey

Will generate a X509Certificate2 with private key from a certificate hosted in Key Vault.

.NOTES
VERSION HISTORY
1.0 | 2023/10/03 | Francois LEON
    initial version
POSSIBLE IMPROVEMENT
    -
#>
function ConvertTo-X509Certificate2 {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    #[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword","")]
    param(
        [parameter(Mandatory,ParameterSetName="pfx")]
        [ValidateScript({
            if((Test-Path $_) -AND ($_ -like '*.pfx')){$true}
            else{throw "Path $_ is not valid"}
        })]
        [String]$PfxPath,
        [parameter(Mandatory,ParameterSetName="pem")]
        [ValidateScript({
            if((Test-Path $_) -AND ($_ -like '*.pem')){$true}
            else{throw "Path $_ is not valid"}
        })]
        [String]$PemPath,
        [parameter(Mandatory,ParameterSetName="crt")]
        [ValidateScript({
            if((Test-Path $_) -AND ($_ -like '*.crt')){$true}
            else{throw "Path $_ is not valid"}
        })]
        [String]$CrtPath,
        [parameter(Mandatory,ParameterSetName="cer")]
        [ValidateScript({
            if((Test-Path $_) -AND ($_ -like '*.cer')){$true}
            else{throw "Path $_ is not valid"}
        })]
        [String]$CerPath,
        [parameter(ParameterSetName="pfx")]
        [ValidateScript({
            if($_.Length -gt 0){$true}
            else{throw 'SecureString argument contained no data.'}
        })]
        [securestring]$Password,
        [parameter(ParameterSetName="pem")]
        [ValidateScript({
            if((Test-Path $_) -AND ( $(get-content $_ | select-object -First 1) -eq '-----BEGIN PRIVATE KEY-----' )){$true}
            else{throw "Path $_ is not valid or private key is not visible"}
        })]
        [string]$PrivateKeyPath,
        [parameter(Mandatory,ParameterSetName="keyvault")]
        [string]$KeyVaultCertificatePath, #https://ubuntukv415745.vault.azure.net/certificates/test/5d69153b75214245ab72fa21b9c06bfb
        [parameter(Mandatory,ParameterSetName="keyvault")]
        [string]$AccessToken, #(Get-AzAccessToken -Resource "https://vault.azure.net").Token
        [parameter(ParameterSetName="keyvault")]
        [string]$APIVersion = '7.3',
        [parameter(ParameterSetName="keyvault")]
        [switch]$ExportPrivateKey
    )

    Begin {
        Write-Verbose "[$((Get-Date).TimeofDay)] Starting $($myinvocation.mycommand)"

        # Just keep what we need to avoid useless switch iteration
        $PSBoundParameters.Remove('KeyVaultAccessToken') | Out-Null
        $PSBoundParameters.Remove('ExportPrivateKey') | Out-Null
        $PSBoundParameters.Remove('PrivateKeyPath') | Out-Null
        $PSBoundParameters.Remove('Password') | Out-Null
        $PSBoundParameters.Remove('AccessToken') | Out-Null
        $PSBoundParameters.Remove('APIVersion') | Out-Null
        $PSBoundParameters.Remove('ExportPrivateKey') | Out-Null

    } #begin

    Process {
        switch ($PSBoundParameters.Keys) {

            'CerPath' {
                #Even if it's not the same format crt and cer is using the same method. I will duplicate code for readability.
                [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($(Get-Item -Path $CerPath))
                break
            }

            'CrtPath' {
                [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($(Get-Item -Path $CrtPath))
                break
            }

            'PfxPath' {
                if($Password){
                    #Means private key protected by password
                    # Means Linux/Windows/MacOS running on Powershell 7 (Yes v6 does not count :D)
                    [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($(Get-Item -Path $PfxPath),$(ConvertFrom-SecureString -SecureString $Password -AsPlainText))
                    break
                }
                else{
                    #Means no password to protect the private key
                    [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($(Get-Item -Path $PfxPath))
                    break
                }
            }

            'PemPath' {
                if($PrivateKeyPath){
                    #Means private key protected by password
                    #openssl pkcs12 -in ./scomnewbie.pfx -out ./scomnewbie2.pem  # Privatekey will be encrypted + no -nodes means passphrase required
                    #openssl rsa -in ./scomnewbie2.pem -out privatekey_rsa.key  #Enter passphrase + decode PK
                    [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($(Get-Item -Path $PemPath),$(Get-Item -Path $PrivateKeyPath))
                    break
                }
                else{
                    #Means no password to protect the private key
                    #openssl pkcs12 -in ./scomnewbie.pfx -out ./scomnewbie.pem -nodes # WARNING No more password anymore + PK decoded
                    if($(get-content -Path $PemPath) -match '-----BEGIN PRIVATE KEY-----'){
                        [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($(Get-Item -Path $PemPath)) # Make sure private key is not encrypted!
                        break
                    }
                    else{
                        throw "Make sure you're private key is not encrypted"
                    }
                }
            }

            'KeyVaultCertificatePath' {
                if($ExportPrivateKey){
                    $CertInfo = Get-KVCertificateWithPrivateKey -KeyVaultCertificatePath $KeyVaultCertificatePath -AccessToken $AccessToken -APIVersion $APIVersion
                    $pfxUnprotectedBytes = [Convert]::FromBase64String($CertInfo.value)
                    [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pfxUnprotectedBytes)
                }
                else{
                    $CertInfo = Get-KVCertificateWithPublicKey -KeyVaultCertificatePath $KeyVaultCertificatePath -AccessToken $AccessToken -APIVersion $APIVersion
                    if($IsWindows){
                        $cBytes = [System.Text.Encoding]::UTF8.GetBytes($CertInfo.cer)
                        [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cBytes)
                    }
                    else{
                        $ModCertInfo =@"
-----BEGIN CERTIFICATE-----
$($CertInfo.cer)
-----END CERTIFICATE-----
"@
                        $cBytes = [System.Text.Encoding]::UTF8.GetBytes($ModCertInfo)
                        [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cBytes)
                    }
                }
            }
        }#end switch
    } #process

    End {
        Write-Verbose "[$((Get-Date).TimeofDay)] Ending $($myinvocation.mycommand)"
    } #end
}