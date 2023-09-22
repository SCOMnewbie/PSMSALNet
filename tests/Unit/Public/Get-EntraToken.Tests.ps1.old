BeforeAll {
    $Module = 'PSMSALNet'
    $FunctionName = 'Get-EntraToken'

    Remove-Module $Module -ErrorAction SilentlyContinue -Force
    Remove-Item -Path Function:\$($FunctionName)

    . "$PSScriptRoot\..\source\Public\$($FunctionName).ps1"
}

Describe 'Testing <FunctionName> function' {

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
}
