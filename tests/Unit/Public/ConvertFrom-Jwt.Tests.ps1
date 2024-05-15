$ProjectPath = "$PSScriptRoot\..\..\.." | Convert-Path
$ProjectName = ((Get-ChildItem -Path $ProjectPath\*\*.psd1).Where{
        ($_.Directory.Name -match 'source|src' -or $_.Directory.Name -eq $_.BaseName) -and
        $(try
            {
                Test-ModuleManifest $_.FullName -ErrorAction Stop
            }
            catch
            {
                $false
            } )
    }).BaseName


Import-Module $ProjectName

InModuleScope $ProjectName {
    BeforeAll {

        $BadToken = 'wrongtoken'
        $ValidToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCIsImtpZCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvOWZjNDgwNDAtYmQ4Yy00ZjNmLWI3YjMtZmYxN2NiZjA0YjIwLyIsImlhdCI6MTcxNTcxMjkwMCwibmJmIjoxNzE1NzEyOTAwLCJleHAiOjE3MTU3MTY4MDAsImFpbyI6IkUyTmdZT0MvWmI1b2UwV3dUSzhxZDgyVm1OQklBQT09IiwiYXBwaWQiOiIxZWM5ZWZlZC04YjVhLTQ4ODMtYThjMC01MTA0Y2MxMTg1MjkiLCJhcHBpZGFjciI6IjEiLCJpZHAiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC85ZmM0ODA0MC1iZDhjLTRmM2YtYjdiMy1mZjE3Y2JmMDRiMjAvIiwiaWR0eXAiOiJhcHAiLCJvaWQiOiJjN2U0NDE1MC0zMDc3LTQ3NjgtOGM0Mi03ZGM5OGRhY2I1YjUiLCJyaCI6IjAuQVZ3QVFJREVuNHk5UDAtM3NfOFh5X0JMSUVaSWYza0F1dGRQdWtQYXdmajJNQk5jQUFBLiIsInN1YiI6ImM3ZTQ0MTUwLTMwNzctNDc2OC04YzQyLTdkYzk4ZGFjYjViNSIsInRpZCI6IjlmYzQ4MDQwLWJkOGMtNGYzZi1iN2IzLWZmMTdjYmYwNGIyMCIsInV0aSI6IjVTcThxMXJhemtHdFdZT2t6Q1k5QUEiLCJ2ZXIiOiIxLjAiLCJ4bXNfdGNkdCI6MTU5MzYwMjgyN30.RdW8_Hsd3sAursvPXdK2EuXgh4nEeDzbV43k9o7dkpDiKvtZsc9fvfTcREYedyM_QVo8_S0fa1quPFrwWyn3xfcbQ1evviN1c1N2GSTH0S7ZCcgQlr3MOy-9Yu_inmHWnJFlzsqg-GBjTIGGLmuMz9rHrFpC0f7XRkHfnSULSTkdS3wOyuLvxeEhnZerL3zu9YlHMI2L9XEjJzKWPfAqxlzw2P442FYTwp_TDJwg2A_yzH3fIFCdknBdsSSZSVdJA7ly2VEXgyi8TpuCiYyxcfq0sHeQGqUxTFzUFO3qsZy0LE63AdBOj1foRrn5MB8vEX16StL-mWbZvJlKUzdpEQ'
    }

    Describe ConvertFrom-Jwt {
        Context 'With wrong value' {

            It 'Should return invalid token' {
                $v = ConvertFrom-Jwt -Token $BadToken
                $v | Should -Be -ExpectedValue 'Invalid token'
            }
        }

        Context 'With good value' {
            It 'Should not throw with good token' {
                { ConvertFrom-Jwt -Token $ValidToken} | Should -not -Throw
            }

            It 'Should contain kid property in header' {
                $Kid = (ConvertFrom-Jwt -Token $ValidToken).Tokenheader.kid
                $Kid | Should -BeExactly 'L1KfKFI_jnXbwWc22xZxw1sUHH0'
            }
        }
    }
}
