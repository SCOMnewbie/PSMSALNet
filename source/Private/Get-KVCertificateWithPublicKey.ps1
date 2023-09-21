function Get-KVCertificateWithPublicKey
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$KeyVaultCertificatePath, #https://ubuntukv415745.vault.azure.net/certificates/test/5d69153b75214245ab72fa21b9c06bfb
        [Parameter(Mandatory)]
        [string]$AccessToken,
        [string]$APIVersion = '7.3'
    )

    # Force TLS 1.2.
    Write-Verbose 'New-PSAADClientCredential - Force TLS 1.2'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    if ($AccessToken -notlike 'Bearer*')
    {
        $AccessToken = "Bearer $($AccessToken)"
    }

    $Headers = @{
        'Content-Type'  = 'application/json'
        'Authorization' = $AccessToken
    }

    $CertURL = "$($KeyVaultCertificatePath)?api-version=$($APIVersion)"
    #$certURL = "https://ubuntukv415745.vault.azure.net/certificates/test/5d69153b75214245ab72fa21b9c06bfb?api-version=$APIVersion"

    Invoke-RestMethod -Uri $certURL -Headers $Headers
}
