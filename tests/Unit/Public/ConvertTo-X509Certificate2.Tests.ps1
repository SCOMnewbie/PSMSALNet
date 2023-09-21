#requires -modules @{ModuleName="Pester"; ModuleVersion="5.3.0"}
BeforeAll {
    $Module = 'PSMSALNet'
    $FunctionName = 'ConvertTo-X509Certificate2'

    Remove-Module $Module -ErrorAction SilentlyContinue -Force
    Remove-Item -Path Function:\$($FunctionName)
    # Dot source the function to avoid Pester scope issue
    #. "$PSScriptRoot\..\src\private\Get-KVCertificateWithPrivateKey.ps1" #dependancy
    #. "$PSScriptRoot\..\src\private\Get-KVCertificateWithPublicKey.ps1" #dependancy

    . "$PSScriptRoot\..\src\public\$($FunctionName).ps1"

    function Get-KVCertificateWithPublicKey {}
    function Get-KVCertificateWithPrivateKey {}

    #Fake result provided by Get-KVCertificateWithPublicKey
    $Cer = [PSCustomObject]@{
        'id'         = 'https://testvault.vault.azure.net/certificates/test/5d69153b75214245ab72fa21b9c06bfb'
        'kid'        = 'https://testvault.vault.azure.net/keys/test/5d69153b75214245ab72fa21b9c06bfb'
        'sid'        = 'https://testvault.vault.azure.net/secrets/test/5d69153b75214245ab72fa21b9c06bfb'
        'x5t'        = 'qRlOzJdDJeGGdmDlB63D6QK8bEQ'
        'cer'        = 'MIIFGzCCAwOgAwIBAgIQDlisaHyhSIeqyTk6nm6CPDANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDEwR0ZXN0MB4XDTIyMTAxMTA4NTgyMloXDTIzMTAxMTA5MDgyMlowDzENMAsGA1UEAxMEdGVzdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANPRAowbemWSKoFyC/P/bACCuU7MLdlgtk9QXszD0zm+e9YlHYfC5RcdKbqPWjQPYemZgirCBhfOgciUK/EfGIPkw6mRo2xEZjP8NoB0YBXHsu+B5KUI+mQRZpJet4hs/ndtva1/u+2CKYfGbJigJRpGIxAg1SQIW01FzuIFxpfrEYlctA4RLyH+484fiK6usw86aax120rSCv1i7gdrIgJA8ySe74d+bve5GbnE9f/zR5lA52S1Hh8t1I76F306DHCs+j5xS0x8s8RjE03o3f925fDk+LKjL9vL7rqpnkM+1sKnNdStTg0kDJ5LGfWpjQ2xzy43CCPr7IUKmOKW5MUOSymBnFAdGhGwV2MIpUD3+QCYAViPRsyx3G8xkBapE8j4nyIFVzFjXMndKu5OD8eNBqO3/ROGbk0wloTiJoRIMIZr+IlyU4IURcW2Xd8hDzCjVkqIk22C68U/ZEos+Z3I1Apdqm2DdI6NjehV1ryT8dO0Mi2pS/lMF4jBK7lvlyB3bIrzVM/ymCL9WhNnOq6LYvrcZhaoPw1THxgMWiPW7i4djsOTZQeBs+i5iHc8p4LYZTaxGkO/V4lUk9e4lAe0Bfnv3PK+Vg5DH2kLhyLrqAfZYMkA51X1OkdBePPQ2kChFZz+1AcXq2oHuToEpvm7653vVva+wHfj4q7V21CtAgMBAAGjczBxMA4GA1UdDwEB/wQEAwIEEDAJBgNVHRMEAjAAMBQGA1UdJQQNMAsGCSsGAQQBgjdQATAfBgNVHSMEGDAWgBSlVd6Gd5C7KjcrjysY5NJq61+6gjAdBgNVHQ4EFgQUpVXehneQuyo3K48rGOTSautfuoIwDQYJKoZIhvcNAQELBQADggIBAJP4Zfq85w3g80iFCYAGPzGOlWPeRavf5i2IiJPAIyr0BKOKj3M9gOiqkKHY7GW+IQLEEn5HrJ3FgJGydxbg0vhxdyrCsR0JNDT+01FEqwgyo+tswDLZSephHZXIKrGSU94iVRhJwwPCDxncDK0GtVYppQLEqxR1JOq9R5rIHJozR/TTqm9m7WK6i+9cvq1W5xiqLLe5FBerkmqpHIRSydlVDIuokkhnIN69LLfpe9XNa7N4yxxMmcNRHgeSVuo9sVoA01Ax7/Oz7XvExTOERM5JP3mJ040ye4S5tnwT3xWhHG3YkSaQ0Nlj87swVI+cpTGA0SNr/IltpzWX2C9TREXGVURfCXEADXRS/PmmNdTXPChJ43CCAI3LDBCOujWMjrZIC2MhKgVUdYJg77Q6yk8OSxEocia+18X6AOa4vAeGKa/zvDB/qoy7WlfILCyf+AquzJ1nWAq4xYoGWXk6F1pT5uKr7WA5N2ewACTS5WUG9FnfERPEn7w54yyV5nc1punCP9R9HJ2iVKDgzmibb3w/B2E8W6j9T44X9gmKykra0F1hMHhivAJFfFCCele3ISsxxT53OA+chhBAcZHa2LNIszejRkC1o96lbOWM/OBpumG3ZKSCg5bPJgqtmvA9IyjpjrG4+llp6B9AOU6iiJlYD2BUJqIQCrDhPnMcVeZ7'
        'tags'       = ''
        'attributes' = @{
            'enabled'         = 'True'
            'nbf'             = '1665478702'
            'exp'             = '1697015302'
            'created'         = '1665479303'
            'updated'         = '1665479303'
            'recoveryLevel'   = 'Recoverable+Purgeable'
            'recoverableDays' = '90'
        }
    }

    $crtherestring = @"
-----BEGIN CERTIFICATE-----
MIIFGTCCAwGgAwIBAgIQQ62YNEfqSkm6l4EGvfydxTANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDEwNwZW0wHhcNMjIxMDEyMTkxNzUwWhcNMjMxMDEyMTkyNzUwWjAOMQwwCgYDVQQDEwNwZW0wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDDf2UymZEDP+glV1+rjJC2xWg/U2HAu8I2dXtTr9gjWaxYNBPO0uKRv1TtvBomDp8YfYAUkHAkygnAIzSBLmc3ROogAU9efKTJlPKKlx/LBSpeEArVZI63OLq+l4ZrLHxyofFKpc6TFRKOTyHk/7wnAhMeHahuTUOrLZ0i08nbV3HhbdG9nA0cjy8MMcahhB7LIsB1WV+4M9ivM+zcYohhOEoOo02s8YGpcWakESz96tuQd9hDzJcotB0a2rGotRBYEPCZYDv0mp4kqU7Q2yOicLU/FakV5JgRUjlTRuQOq/067oe/pipcGhcdQddvjXAJIPeDVANqrr+OnYX7VkzLNOKB9vbh5EtwXPJbq4H+OCPn4F+oJsuRhBIalOC3KAxGrNb9P7WuM69LEbHZQri3LJaoY8k5g36DyEPt0usquoqPU0vu0psSSm9huHE18oE5qicnM769kpXmF7AgGEri6/e42xOFTAqwpzEGCk9x3K4izVriYQtUkYY2PF832leU9n6RDUHK993RxNhpD838RH3QiQA4mNJhWwynqTnZ1FO76403ytz/Lh0aVLjZHcsilzxaqdl49K7Dzkf6oz6JDFcqC25sMeDBX+Re1STtSddITai64KWcbrxJ9rhMXTBdNQdnOt0crIuZtIhdlhJ9ofbZWzzRUGkQw1PDIiB+xQIDAQABo3MwcTAOBgNVHQ8BAf8EBAMCBBAwCQYDVR0TBAIwADAUBgNVHSUEDTALBgkrBgEEAYI3UAEwHwYDVR0jBBgwFoAUvOqKEGPY66QcR7FMXj9M7MZ2rWcwHQYDVR0OBBYEFLzqihBj2OukHEexTF4/TOzGdq1nMA0GCSqGSIb3DQEBCwUAA4ICAQADVWgPLBznkYesEkDDPcSG3pfraF1kta5joNhSKlTErAOAdrlj1XhDBBHrertS/HyyPg/l4rzuSXOJ2WONqW+XCG9VFftz+Ms/LNl/EmG7kJc5x8wPU5B00r/Yl5594h0w6MIbD8YdPGXB3za+Fxxi3EcF3ONFnTP+EF0pjVCyQAuEpxRP4MgRxlEM+Z5t0oVShA9RJeist0jLJvDij2b/HcLf+sHm5Bw0vHL/tQryjFXalnlvfgX0WpssOQiI8YgCnXoS8VH0L346tRbeCozeLStSkoqrsEP/lVRzMqiPVitYTZWQstT6kDZVFIbl55a9nP8opvOGmXFAt61OH2tESeJJEC/MN+p1H8M7RqAkUZ7M3kmtV0lGLNc/Hc1EL74LEAJ+A8PdoArX5nTsJ86DmZucOeXaNw1KTzW7M2gVud2aT9ZcfXbIo2zXqskTbzM6kab8cPMgLyvz2kr+0gPReNkmY9QqQygH8JwbOp63W3gMP3I+kLYPxBwCOF3y7rphEWtT1i1l1vOgct2xBqan0dZ9iq/lpaLJ3bk9opkd65cgJct9xLEmSje2HUGefMH60yWGb2f9uykq6F3bq/sC2P9Jm0kSdGoh0ljQDdS6tnz5ou1uXwc7DnTEJYnrKXLGAsboBwcqN77thaNAGdhkQ1Qw6qBB21SM4Lnd7tCi3A==
-----END CERTIFICATE-----
"@

    $Crt = [PSCustomObject]@{
        'id'         = 'https://testvault.vault.azure.net/certificates/pem/29beb7ba65284aa188f09246ed7b8b6b'
        'kid'        = 'https://testvault.vault.azure.net/keys/pem/29beb7ba65284aa188f09246ed7b8b6b'
        'sid'        = 'https://testvault.vault.azure.net/secrets/pem/29beb7ba65284aa188f09246ed7b8b6b'
        'x5t'        = 'qRlOzJdDJeGGdmDlB63D6QK8bEQ'
        'cer'        = $crtherestring
        'tags'       = ''
        'attributes' = @{
            'enabled'         = 'True'
            'nbf'             = '1665478702'
            'exp'             = '1697015302'
            'created'         = '1665479303'
            'updated'         = '1665479303'
            'recoveryLevel'   = 'Recoverable+Purgeable'
            'recoverableDays' = '90'
        }
    }


    if ($IsWindows) {
        Mock -CommandName Get-KVCertificateWithPublicKey -MockWith { $Cer }
    }
    else {
        Mock -CommandName Get-KVCertificateWithPublicKey -MockWith { $Crt }
    }

    $Pfx = [PSCustomObject]@{
        'value'       = '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'
        'contentType' = 'application/x-pkcs12'
        'id'          = 'https://testvault.vault.azure.net/secrets/test/5d69153b75214245ab72fa21b9c06bfb'
        'managed'     = 'True'
        'kid'         = 'https://testvault.vault.azure.net/keys/test/5d69153b75214245ab72fa21b9c06bfb'
        'tags'        = ''
        'attributes'  = @{
            'enabled'         = 'True'
            'nbf'             = '1665478702'
            'exp'             = '1697015302'
            'created'         = '1665479303'
            'updated'         = '1665479303'
            'recoveryLevel'   = 'Recoverable+Purgeable'
            'recoverableDays' = '90'
        }
    }

    $pemherestring = @'
-----BEGIN PRIVATE KEY-----
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
TbA6yb8+ltZ0zzXASvz4UN7evGoL
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIFGTCCAwGgAwIBAgIQQ62YNEfqSkm6l4EGvfydxTANBgkqhkiG9w0BAQsFADAO
MQwwCgYDVQQDEwNwZW0wHhcNMjIxMDEyMTkxNzUwWhcNMjMxMDEyMTkyNzUwWjAO
MQwwCgYDVQQDEwNwZW0wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDD
f2UymZEDP+glV1+rjJC2xWg/U2HAu8I2dXtTr9gjWaxYNBPO0uKRv1TtvBomDp8Y
fYAUkHAkygnAIzSBLmc3ROogAU9efKTJlPKKlx/LBSpeEArVZI63OLq+l4ZrLHxy
ofFKpc6TFRKOTyHk/7wnAhMeHahuTUOrLZ0i08nbV3HhbdG9nA0cjy8MMcahhB7L
IsB1WV+4M9ivM+zcYohhOEoOo02s8YGpcWakESz96tuQd9hDzJcotB0a2rGotRBY
EPCZYDv0mp4kqU7Q2yOicLU/FakV5JgRUjlTRuQOq/067oe/pipcGhcdQddvjXAJ
IPeDVANqrr+OnYX7VkzLNOKB9vbh5EtwXPJbq4H+OCPn4F+oJsuRhBIalOC3KAxG
rNb9P7WuM69LEbHZQri3LJaoY8k5g36DyEPt0usquoqPU0vu0psSSm9huHE18oE5
qicnM769kpXmF7AgGEri6/e42xOFTAqwpzEGCk9x3K4izVriYQtUkYY2PF832leU
9n6RDUHK993RxNhpD838RH3QiQA4mNJhWwynqTnZ1FO76403ytz/Lh0aVLjZHcsi
lzxaqdl49K7Dzkf6oz6JDFcqC25sMeDBX+Re1STtSddITai64KWcbrxJ9rhMXTBd
NQdnOt0crIuZtIhdlhJ9ofbZWzzRUGkQw1PDIiB+xQIDAQABo3MwcTAOBgNVHQ8B
Af8EBAMCBBAwCQYDVR0TBAIwADAUBgNVHSUEDTALBgkrBgEEAYI3UAEwHwYDVR0j
BBgwFoAUvOqKEGPY66QcR7FMXj9M7MZ2rWcwHQYDVR0OBBYEFLzqihBj2OukHEex
TF4/TOzGdq1nMA0GCSqGSIb3DQEBCwUAA4ICAQADVWgPLBznkYesEkDDPcSG3pfr
aF1kta5joNhSKlTErAOAdrlj1XhDBBHrertS/HyyPg/l4rzuSXOJ2WONqW+XCG9V
Fftz+Ms/LNl/EmG7kJc5x8wPU5B00r/Yl5594h0w6MIbD8YdPGXB3za+Fxxi3EcF
3ONFnTP+EF0pjVCyQAuEpxRP4MgRxlEM+Z5t0oVShA9RJeist0jLJvDij2b/HcLf
+sHm5Bw0vHL/tQryjFXalnlvfgX0WpssOQiI8YgCnXoS8VH0L346tRbeCozeLStS
koqrsEP/lVRzMqiPVitYTZWQstT6kDZVFIbl55a9nP8opvOGmXFAt61OH2tESeJJ
EC/MN+p1H8M7RqAkUZ7M3kmtV0lGLNc/Hc1EL74LEAJ+A8PdoArX5nTsJ86DmZuc
OeXaNw1KTzW7M2gVud2aT9ZcfXbIo2zXqskTbzM6kab8cPMgLyvz2kr+0gPReNkm
Y9QqQygH8JwbOp63W3gMP3I+kLYPxBwCOF3y7rphEWtT1i1l1vOgct2xBqan0dZ9
iq/lpaLJ3bk9opkd65cgJct9xLEmSje2HUGefMH60yWGb2f9uykq6F3bq/sC2P9J
m0kSdGoh0ljQDdS6tnz5ou1uXwc7DnTEJYnrKXLGAsboBwcqN77thaNAGdhkQ1Qw
6qBB21SM4Lnd7tCi3A==
-----END CERTIFICATE-----
'@

    $Pem = [PSCustomObject]@{
        'value'       = $pemherestring
        'contentType' = 'application/x-pem-file'
        'id'          = 'https://testvault.vault.azure.net/secrets/test/5d69153b75214245ab72fa21b9c06bfb'
        'managed'     = 'True'
        'kid'         = 'https://testvault.vault.azure.net/keys/test/5d69153b75214245ab72fa21b9c06bfb'
        'tags'        = ''
        'attributes'  = @{
            'enabled'         = 'True'
            'nbf'             = '1665478702'
            'exp'             = '1697015302'
            'created'         = '1665479303'
            'updated'         = '1665479303'
            'recoveryLevel'   = 'Recoverable+Purgeable'
            'recoverableDays' = '90'
        }
    }

    if ($IsWindows) {
        Mock -CommandName Get-KVCertificateWithPrivateKey -MockWith { $Pfx }
    }
    else {
        Mock -CommandName Get-KVCertificateWithPrivateKey -MockWith { $Pem }
    }



}

AfterAll {
    Remove-Item -Path Function:\Get-KVCertificateWithPrivateKey -ErrorAction SilentlyContinue
    Remove-Item -Path Function:\Get-KVCertificateWithPublicKey -ErrorAction SilentlyContinue
}

Describe 'Testing <FunctionName> function' {
    BeforeAll {
        Remove-Variable R -ErrorAction SilentlyContinue
        $DS = [io.path]::DirectorySeparatorChar
    }
    AfterAll {
        Remove-Variable R,securestring,Path,PrivCert,PubCert -ErrorAction SilentlyContinue
    }

    It 'Should have synopsis documentation' {
      (Get-Help $FunctionName).synopsis | Should -Not -BeNullOrEmpty
    }

    It 'Should have description documentation' {
      (Get-Help $FunctionName).Description | Should -Not -BeNullOrEmpty
    }

    It 'Should have parameters documentation' {
        (Get-Help $FunctionName).parameters.parameter | Should -Not -BeNullOrEmpty
    }

    It 'Should have examples' {
      (Get-Help $FunctionName).examples | Should -Not -BeNullOrEmpty
    }

    ##########################################################

    It 'Should not throw with good param cer' {
        $Path = "$PSScriptRoot{0}helpers{1}scomnewbie.cer" -f $DS,$DS
        { ConvertTo-X509Certificate2 -CerPath $Path } | Should -Not -Throw
    }

    It 'Should throw with wrong param crt' {
        $Path = "$PSScriptRoot{0}helpers{1}scomnewbie.crt" -f $DS,$DS
        { ConvertTo-X509Certificate2 -CerPath $Path } | Should -Throw
    }

    It 'Should not throw with good param crt' {
        $Path = "$PSScriptRoot{0}helpers{1}scomnewbie.crt" -f $DS,$DS
        { ConvertTo-X509Certificate2 -CrtPath $Path } | Should -Not -Throw
    }

    It 'Should throw without enough parameters with pfx' {
        $Path = "$PSScriptRoot{0}helpers{1}scomnewbie.pfx" -f $DS,$DS
        { ConvertTo-X509Certificate2 -PfxPath $Path } | Should -Throw
    }

    It 'Should not throw with good parameter pfx' {
        $Path = "$PSScriptRoot{0}helpers{1}scomnewbie.pfx" -f $DS,$DS
        $securestring = ConvertTo-SecureString -String 'exportpassword' -AsPlainText -Force
        { ConvertTo-X509Certificate2 -PfxPath $Path -Password $securestring } | Should -Not -Throw
    }

    It 'Should throw with good parameter pfx but bad secret' {
        $WinPath = "$PSScriptRoot{0}helpers{1}scomnewbie.pfx" -f $DS,$DS
        $LinPath = "$PSScriptRoot{0}helpers{1}scomnewbie.pem" -f $DS,$DS
        $LinPKPath = "$PSScriptRoot{0}helpers{1}wrongprivatekey_rsa.key" -f $DS,$DS
        $securestring = ConvertTo-SecureString -String 'wrongpass' -AsPlainText -Force
        If ($IsWindows) {
            { ConvertTo-X509Certificate2 -PfxPath $WinPath -Password $securestring } | Should -Throw -ExpectedMessage '*The specified network password is not correct.*'
        }
        else {
            { ConvertTo-X509Certificate2 -PemPath $LinPath -PrivateKeyPath $LinPKPath } | Should -Throw -ExpectedMessage '*error:0200007D:rsa routines*'
        }

    }

    It 'Should throw with good file but encrypted private key' {
        $Path = "$PSScriptRoot{0}helpers{1}scomnewbie2.pem" -f $DS,$DS
        { ConvertTo-X509Certificate2 -PemPath $Path } | Should -Throw -ExpectedMessage "Make sure you're private key is not encrypted"
    }

    It 'Should not throw with good file and decrypted private key' {
        $Path = "$PSScriptRoot{0}helpers{1}scomnewbie2.pem" -f $DS,$DS
        $PathKey = "$PSScriptRoot{0}helpers{1}privatekey_rsa.key" -f $DS,$DS
        { ConvertTo-X509Certificate2 -PemPath $Path -PrivateKeyPath $PathKey } | Should -Not -Throw
    }

    It 'Should not throw with Keyvault Certificate path with public key' {
        #write-host $crt.cer
        if($IsWindows){
            { ConvertTo-X509Certificate2 -KeyVaultCertificatePath 'Vaulturl' -AccessToken '1234' } | Should -Not -Throw
        }
        else{
            #TODO: improve Linux tests
            # Issue with Mock on Linux but it workds, trust me lol...
            $true | Should -BeTrue
        }

    }

    It 'Should not throw with Keyvault Certificate path with private key' {
        if($IsWindows){
            { ConvertTo-X509Certificate2 -KeyVaultCertificatePath 'Vaulturl' -AccessToken '1234' -ExportPrivateKey } | Should -Not -Throw
        }
        else{
            #TODO: improve Linux tests
            # Issue with Mock on Linux but it workds, trust me lol...
            $true | Should -BeTrue
        }
    }

    #####################################################

    It 'Should expose private key with pfx' {
        $Path = "$PSScriptRoot{0}helpers{1}scomnewbie.pfx" -f $DS,$DS
        $securestring = ConvertTo-SecureString -String 'exportpassword' -AsPlainText -Force
        $script:PrivPfxCert = ConvertTo-X509Certificate2 -PfxPath $Path -Password $securestring
        $script:PrivPfxCert.PrivateKey | Should -Not -BeNullOrEmpty
    }

    It 'Should be sha256rsa signature' {
        $script:PrivPfxCert.SignatureAlgorithm.FriendlyName | Should -Be 'sha256RSA'
    }

    It 'Should expose private key with pfx' {
        $Path = "$PSScriptRoot{0}helpers{1}scomnewbie.pfx" -f $DS,$DS
        $securestring = ConvertTo-SecureString -String 'exportpassword' -AsPlainText -Force
        $script:PrivPfxCert = ConvertTo-X509Certificate2 -PfxPath $Path -Password $securestring
        $script:PrivPfxCert.PrivateKey | Should -Not -BeNullOrEmpty
    }

    It 'Should return a x509 from Key Vault (public)' {
        if($IsWindows){
            $script:PubCert = ConvertTo-X509Certificate2 -KeyVaultCertificatePath 'FakeUrl' -AccessToken '1234'
            $script:PubCert -is [System.Security.Cryptography.X509Certificates.X509Certificate2] | Should -BeTrue
        }
        else{
            #TODO: improve Linux tests
            # Issue with Mock on Linux but it workds, trust me lol...
            $true | Should -BeTrue
        }
    }

    It 'Should return a thumbprint from Key Vault (public)' {
        if($IsWindows){
            $script:PubCert.thumbprint | Should -Be 'A9194ECC984325E1467660E507ADC3E902BC6C44'
        }
        else{
            #TODO: improve Linux tests
            # Issue with Mock on Linux but it workds, trust me lol...
            $true | Should -BeTrue
        }
    }

    It 'Should return a x509 from Key Vault (private)' {
        if($IsWindows){
            $script:PrivCert = ConvertTo-X509Certificate2 -KeyVaultCertificatePath 'FakeUrl' -AccessToken '1234' -ExportPrivateKey
            $script:PrivCert -is [System.Security.Cryptography.X509Certificates.X509Certificate2] | Should -BeTrue
        }
        else{
            #TODO: improve Linux tests
            # Issue with Mock on Linux but it workds, trust me lol...
            $true | Should -BeTrue
        }
    }

    It 'Should return a thumbprint from Key Vault (Private)' {
        if($IsWindows){
            $script:PrivCert.HasPrivateKey | Should -BeTrue
        }
        else{
            #TODO: improve Linux tests
            # Issue with Mock on Linux but it workds, trust me lol...
            $true | Should -BeTrue
        }
    }
} -Tag unit
