function Get-KVCertificateWithPrivateKey
{
    <#
      .SYNOPSIS
      This is a function to download certificate information from Azure KeyVault and export the private key as well.

      .DESCRIPTION
      This is a function to download certificate information from Azure KeyVault and export the private key as well.

      .EXAMPLE
      TODO: Write examples

      .PARAMETER KeyVaultCertificatePath
      The KeyVaultCertificatePath parameter is the path of the Keyvault certificate.

      .PARAMETER AccessToken
      The AccessToken parameter is the JWT you have to provide to do the action.

      .PARAMETER APIVersion
      The APIVersion parameter is the version of the Keyvault API.

    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$KeyVaultCertificatePath, #https://ubuntukv415745.vault.azure.net/certificates/test/5d69153b75214245ab72fa21b9c06bfb
        [Parameter(Mandatory)]
        [string]$AccessToken,
        [string]$APIVersion = '7.3'
    )

    # Force TLS 1.2.
    Write-Verbose "[$((Get-Date).TimeofDay)] Starting $($myinvocation.mycommand)"
    Write-Verbose "[$((Get-Date).TimeofDay)] Get-KVCertificateWithPrivateKey - Force TLS 1.2"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    if ($AccessToken -notlike 'Bearer*')
    {
        $AccessToken = "Bearer $($AccessToken)"
    }

    $Headers = @{
        'Content-Type'  = 'application/json'
        'Authorization' = $AccessToken
    }

    $splat = @{
        'KeyVaultCertificatePath' = $KeyVaultCertificatePath
        'AccessToken'             = $AccessToken
        'APIVersion'              = $APIVersion
    }

    $CertInfo = Get-KVCertificateWithPublicKey @splat

    if ($null -eq $CertInfo.sid)
    {
        throw 'Unable to find private key information'
    }

    #Now we have certificate information let's find private key info
    Invoke-RestMethod -Uri "$($CertInfo.sid)?api-version=$($APIVersion)" -Headers $Headers
}
