function ConvertFrom-Jwt
{
    <#
    .SYNOPSIS
    This function will decode a base64 JWT token.
    .DESCRIPTION
    Big thank you to both Darren Robinson (https://github.com/darrenjrobinson/JWTDetails/blob/master/JWTDetails/1.0.0/JWTDetails.psm1) and
    Mehrdad Mirreza in the comment of the blog post (https://www.michev.info/Blog/Post/2140/decode-jwt-access-and-id-tokens-via-powershell)
    I've used both article for inspiration because:
    Darren does not have header wich is a mandatory peace according to me and Mehrdad does not have signature which is also a mandatory piece.
    .PARAMETER Token
        Specify the access token you want to decode
    .EXAMPLE
    PS> ConvertFrom-Jwt -Token "ey...."

    "will decode the token"
    .NOTES
    VERSION HISTORY
    1.0 | 2021/07/06 | Francois LEON
        initial version
    POSSIBLE IMPROVEMENT
        -
    #>
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    Write-Verbose "[$((Get-Date).TimeofDay)] Starting $($myinvocation.mycommand)"

    Write-Verbose "[$((Get-Date).TimeofDay)] $($myinvocation.mycommand) - Remove Bearer word just in case"
    $Token = $Token.Replace('Bearer ', '')

    try
    {
        # Validate as per https://tools.ietf.org/html/rfc7519
        # Access and ID tokens are fine, Refresh tokens will not work
        if (!$Token.Contains('.') -or !$Token.StartsWith('eyJ'))
        {
            Throw 'Invalid token'
        }

        # Extract header and payload
        $tokenheader, $tokenPayload, $tokensignature = $Token.Split('.').Replace('-', '+').Replace('_', '/')[0..2]

        # Fix padding as needed, keep adding '=' until string length modulus 4 reaches 0
        while ($tokenheader.Length % 4)
        {
            Write-Debug 'Invalid length for a Base-64 char array or string, adding ='; $tokenheader += '='
        }
        while ($tokenPayload.Length % 4)
        {
            Write-Debug 'Invalid length for a Base-64 char array or string, adding ='; $tokenPayload += '='
        }
        while ($tokenSignature.Length % 4)
        {
            Write-Debug 'Invalid length for a Base-64 char array or string, adding ='; $tokenSignature += '='
        }

        Write-Verbose "[$((Get-Date).TimeofDay)] $($myinvocation.mycommand) - Base64 encoded (padded) header:`n$tokenheader"
        Write-Verbose "[$((Get-Date).TimeofDay)] $($myinvocation.mycommand) - Base64 encoded (padded) payoad:`n$tokenPayload"
        Write-Verbose "[$((Get-Date).TimeofDay)] $($myinvocation.mycommand) - Base64 encoded (padded) payoad:`n$tokenSignature"

        # Convert header from Base64 encoded string to PSObject all at once
        $header = [System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($tokenheader)) | ConvertFrom-Json

        # Convert payload to string array
        $tokenArray = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($tokenPayload))

        # Convert from JSON to PSObject
        $tokobj = $tokenArray | ConvertFrom-Json

        # Convert Expiry time to PowerShell DateTime
        $orig = (Get-Date -Year 1970 -Month 1 -Day 1 -hour 0 -Minute 0 -Second 0 -Millisecond 0)
        $timeZone = Get-TimeZone
        $utcTime = $orig.AddSeconds($tokobj.exp)
        $hoursOffset = $timeZone.GetUtcOffset($(Get-Date)).hours #Daylight saving needs to be calculated
        $localTime = $utcTime.AddHours($hoursOffset)     # Return local time,

        # Time to Expiry
        $timeToExpiry = ($localTime - (get-date))

        Write-Verbose "[$((Get-Date).TimeofDay)] Ending $($myinvocation.mycommand)"
        [pscustomobject]@{
            Tokenheader         = $header
            TokenPayload        = $tokobj
            TokenSignature      = $tokenSignature
            TokenExpiryDateTime = $localTime
            TokentimeToExpiry   = $timeToExpiry
        }
    }
    catch
    {
        $_.Exception.Message
    }
}
