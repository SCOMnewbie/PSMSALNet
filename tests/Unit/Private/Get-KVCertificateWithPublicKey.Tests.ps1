BeforeAll {
    $Module = 'PSMSALNet'
    $FunctionName = 'Get-KVCertificateWithPublicKey'

    Remove-Module $Module -ErrorAction SilentlyContinue -Force
    Remove-Item -Path Function:\$($FunctionName)

    . "$PSScriptRoot\..\source\Public\$($FunctionName).ps1"
}

Describe 'Testing <FunctionName> function' {

    It 'Test to implement' {
      $true | Should -BeTrue
    }
}
