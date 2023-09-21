function Get-EntraToken {
    <#
    .SYNOPSIS
    This function will sync members from an onprem group to an AAD group. AD is the source of truth.
    .DESCRIPTION
    Important: The is a little bit of harcoded value because this module has been designed for a specific purpose but this function is easily extendable to generic usage.
    This function will sync members from an onprem group to an AAD group. AD is the source of truth. This command will take only AD users account where the attribute
    extensionAttribute12 is set to SyncToAzureAD. Indeed, we want to be sure users we will mirror belongs to AAD already.
    This function will run using a deleguated API permission under a specific user service account.
    .PARAMETER DisplayName
    Specify the name of the group you create in AAD.
    .PARAMETER MailNickname
    Specify the mailnickname attribute you will assign.In our case the AWS projectID.
    .PARAMETER OnPremGroupToCopyFrom
    Specify the samAccountNAme of the Onprem AD group. You will copy members from this group too with this command.
    .EXAMPLE

    Sync-AADGroupFromAD -DisplayName "Test_FL_graph-owner" -MailNickname "123456789012" -OnPremGroupToCopyFrom "myADgroup" -Verbose

    Will mirror the onprem group to an AAD group. In other words, this command can Add/Remove members to an AAD group.

    .NOTES
    VERSION HISTORY
    1.0 | 2020/12/02 | Francois LEON
        initial version
    POSSIBLE IMPROVEMENT
        -
    #>
    [cmdletbinding()]
    [OutputType([Microsoft.Identity.Client.AuthenticationResult])]
    param
    (
        # Identifier of the client requesting the token.
        [Parameter(Mandatory, ParameterSetName = 'ClientCredentialFlowSecret')]
        [switch]$ClientCredentialFlowWithSecret,

        # Identifier of the client requesting the token.
        [Parameter(Mandatory, ParameterSetName = 'ClientCredentialFlowCertificate')]
        [switch]$ClientCredentialFlowWithCertificate,

        [Parameter(Mandatory, ParameterSetName = 'PublicAuthorizationCodeFlow')]
        [switch]$PublicAuthorizationCodeFlow,

        [Parameter(Mandatory, ParameterSetName = 'DeviceCodeFlow')]
        [switch]$DeviceCodeFlow,

        [Parameter(Mandatory, ParameterSetName = 'WAMFlow')]
        [switch]$WAMFlow,

        [Parameter(Mandatory, ParameterSetName = 'OnBehalfFlowWithSecret')]
        [switch]$OnBehalfFlowWithSecret,

        [Parameter(Mandatory, ParameterSetName = 'OnBehalfFlowWithCertificate')]
        [switch]$OnBehalfFlowWithCertificate,

        [Parameter(Mandatory, ParameterSetName = 'FederatedCredentialFlowWithAssertion')]
        [switch]$FederatedCredentialFlowWithAssertion,

        [Parameter(Mandatory, ParameterSetName = 'OnBehalfFlowWithCertificate')]
        [Parameter(Mandatory, ParameterSetName = 'OnBehalfFlowWithSecret')]
        [Parameter(Mandatory, ParameterSetName = 'FederatedCredentialFlowWithAssertion')]
        [string]$UserAssertion,

        # Identifier of the client requesting the token.
        [Parameter(Mandatory, ParameterSetName = 'SystemManagedIdentity')]
        [switch]$SystemManagedIdentity,

        # Identifier of the client requesting the token.
        [Parameter(Mandatory, ParameterSetName = 'UserManagedIdentity')]
        [switch]$UserManagedIdentity,

        # Identifier of the client requesting the token.
        [Parameter(Mandatory, ParameterSetName = 'ClientCredentialFlowCertificate')]
        [Parameter(Mandatory, ParameterSetName = 'ClientCredentialFlowSecret')]
        [Parameter(Mandatory, ParameterSetName = 'PublicAuthorizationCodeFlow')]
        [Parameter(Mandatory, ParameterSetName = 'UserManagedIdentity')]
        [Parameter(Mandatory, ParameterSetName = 'DeviceCodeFlow')]
        [Parameter(Mandatory, ParameterSetName = 'WAMFlow')]
        [Parameter(Mandatory, ParameterSetName = 'OnBehalfFlowWithCertificate')]
        [Parameter(Mandatory, ParameterSetName = 'OnBehalfFlowWithSecret')]
        [Parameter(Mandatory, ParameterSetName = 'FederatedCredentialFlowWithAssertion')]
        [guid] $ClientId,

        # Secure secret of the client requesting the token.
        [Parameter(Mandatory, ParameterSetName = 'ClientCredentialFlowSecret')]
        [Parameter(Mandatory, ParameterSetName = 'OnBehalfFlowWithSecret')]
        [string] $ClientSecret,

        # Client assertion certificate of the client requesting the token.
        [Parameter(Mandatory, ParameterSetName = 'ClientCredentialFlowCertificate')]
        [Parameter(Mandatory, ParameterSetName = 'OnBehalfFlowWithCertificate')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $ClientCertificate,

        # Will generate a new token on each call with this param
        [Parameter(ParameterSetName = 'ClientCredentialFlowSecret')]
        [Parameter(ParameterSetName = 'ClientCredentialFlowCertificate')]
        [Parameter(ParameterSetName = 'FederatedCredentialFlowWithAssertion')]
        [switch] $WithoutCaching,

        # Instance of Azure Cloud
        [ValidateSet('AzurePublic','AzureChina','AzureUsGovernment','AzureGermany')]
        [Microsoft.Identity.Client.AzureCloudInstance] $AzureCloudInstance = 'AzurePublic',

        # Tenant identifier of the authority to issue token. It can also contain the value "consumers" or "organizations".
        [Parameter(Mandatory, ParameterSetName = 'ClientCredentialFlowCertificate')]
        [Parameter(Mandatory, ParameterSetName = 'ClientCredentialFlowSecret')]
        [Parameter(ParameterSetName = 'PublicAuthorizationCodeFlow')]
        [Parameter(ParameterSetName = 'DeviceCodeFlow')]
        [Parameter(ParameterSetName = 'WAMFlow')]
        [Parameter(Mandatory, ParameterSetName = 'OnBehalfFlowWithCertificate')]
        [Parameter(Mandatory, ParameterSetName = 'OnBehalfFlowWithSecret')]
        [Parameter(Mandatory, ParameterSetName = 'FederatedCredentialFlowWithAssertion')]
        [guid] $TenantId,

        # Address to return to upon receiving a response from the authority.
        [Parameter(Mandatory, ParameterSetName = 'PublicAuthorizationCodeFlow')]
        [Parameter(Mandatory, ParameterSetName = 'DeviceCodeFlow')]
        [Parameter(Mandatory, ParameterSetName = 'WAMFlow')]
        [uri] $RedirectUri,

        #Scope = Resource + Permission
        [parameter(Mandatory)]
        [ValidateSet('Keyvault','ARM','GraphAPI','Storage','Monitor', 'LogAnalytics', 'PostGreSql','Custom')] #TODO: valider Graph API not sure it's working
        [string] $Resource,

        [string] $CustomResource = $null, #https:// ... should be used only with Custom Audience like api://<your api>

        [Parameter(Mandatory, ParameterSetName = 'PublicAuthorizationCodeFlow')]
        [Parameter(Mandatory, ParameterSetName = 'DeviceCodeFlow')]
        [Parameter(Mandatory, ParameterSetName = 'WAMFlow')]
        [Parameter(Mandatory, ParameterSetName = 'OnBehalfFlowWithCertificate')]
        [Parameter(Mandatory, ParameterSetName = 'OnBehalfFlowWithSecret')]
        [string[]] $Permissions, #User.read, Directory.Read ...

        [Parameter(ParameterSetName = 'PublicAuthorizationCodeFlow')]
        [Parameter(ParameterSetName = 'WAMFlow')]
        [Parameter(ParameterSetName = 'DeviceCodeFlow')]
        [string[]]$ExtraScopesToConsent
    )

    Write-Verbose "[$((Get-Date).TimeofDay)] Starting $($myinvocation.mycommand)"

    if ($Resource -eq 'Custom') {
        if ($null -eq $CustomResource) {
            Throw "CustomScope parameter should not be null when you're using Custom audience"
        }
    }

    switch ($Resource) {
        'Keyvault' { $ScopesUri = 'https://vault.azure.net';break }
        'ARM' { $ScopesUri = 'https://management.azure.com';break }
        'GraphAPI' { $ScopesUri = 'https://graph.microsoft.com';break }
        'Storage' { $ScopesUri = 'https://storage.azure.com';break }
        'Monitor' { $ScopesUri = 'https://monitor.azure.com';break }
        'LogAnalytics' { $ScopesUri = 'https://api.loganalytics.io';break }
        'PostGreSql' { $ScopesUri = 'https://ossrdbms-aad.database.windows.net';break }
        default { $ScopesUri = $CustomResource }
    }

    If ($PSBoundParameters[@('ClientCredentialFlowWithSecret','ClientCredentialFlowWithCertificate','SystemManagedIdentity','UserManagedIdentity','FederatedCredentialFlowWithAssertion')]) {
        # In case a user provide api://fsdfsdf/ with a / at the end
        if($CustomResource -match '\\$'){
            [string[]]$scopes = '{0}{1}' -f $ScopesUri,'.default'
        }
        else{
            [string[]]$scopes = '{0}/{1}' -f $ScopesUri,'.default'
        }
    }
    else{
        # Means user may provide one Resource (Azure limitation) but multiple permissions
        $TempArray = @()
        Foreach($Permission in $Permissions){
            if($CustomResource -match '\\$'){
                $TempArray += '{0}{1}' -f $ScopesUri,$Permission
            }
            else{
                $TempArray += '{0}/{1}' -f $ScopesUri,$Permission
            }
        }
        [string[]]$scopes = $TempArray
    }

    Write-Verbose "[$((Get-Date).TimeofDay)] Scope requested are $Scopes"

    #Reset main variables
    [Microsoft.Identity.Client.AuthenticationResult] $AuthenticationResult = $T = $WAMToken = $null

    # This is the memory cache MSAL will use
    if(-not (Get-variable -Name PublicClientApplications -ErrorAction SilentlyContinue)){
        [System.Collections.Generic.List[Microsoft.Identity.Client.IPublicClientApplication]] $script:PublicClientApplications = New-Object 'System.Collections.Generic.List[Microsoft.Identity.Client.IPublicClientApplication]'
    }

    If ($PSBoundParameters[@('ClientCredentialFlowWithSecret','ClientCredentialFlowWithCertificate','OnBehalfFlowWithSecret','OnBehalfFlowWithCertificate','FederatedCredentialFlowWithAssertion')]) {
        Write-Verbose "[$((Get-Date).TimeofDay)] Confidential application selected"
        $ClientApplicationBuilder = [Microsoft.Identity.Client.ConfidentialClientApplicationBuilder]::Create($ClientId)
        #Common Authority can't be used with this flow
        $ClientApplicationBuilder.WithAuthority($AzureCloudInstance,$TenantId) | Out-Null
        if($WithoutCaching){
            Write-Verbose "[$((Get-Date).TimeofDay)] Caching disabled with client credential flow"
            $ClientApplicationBuilder.WithCacheOptions($false)
        }
        else{
            $ClientApplicationBuilder.WithCacheOptions($true)
        }
        switch -regex ($PSBoundParameters.Keys) {
            'ClientCredentialFlowWithSecret|OnBehalfFlowWithSecret' {
                $ClientApplicationBuilder.WithClientSecret($ClientSecret) | Out-Null
                break
            }
            'ClientCredentialFlowWithCertificate|OnBehalfFlowWithCertificate' {
                $ClientApplicationBuilder.WithCertificate($ClientCertificate) | Out-Null
                break
            }
            'FederatedCredentialFlowWithAssertion'{
                #https://learn.microsoft.com/en-us/entra/msal/dotnet/acquiring-tokens/web-apps-apis/confidential-client-assertions
                $ClientApplicationBuilder.WithClientAssertion([Microsoft.Identity.Client.UserAssertion]::new($UserAssertion)) | Out-Null
                break
            }
            default {
                throw 'Should not go there'
            }
        }

    }
    elseif ($PSBoundParameters['SystemManagedIdentity']) {
        Write-Verbose "[$((Get-Date).TimeofDay)] System Managed identity selected"
        $ClientApplicationBuilder = [Microsoft.Identity.Client.ManagedIdentityApplicationBuilder]::Create([Microsoft.Identity.Client.AppConfig.ManagedIdentityId]::SystemAssigned)
    }
    elseif ($PSBoundParameters['UserManagedIdentity']) {
        Write-Verbose "[$((Get-Date).TimeofDay)] User Managed identity selected"
        $ClientApplicationBuilder = [Microsoft.Identity.Client.ManagedIdentityApplicationBuilder]::Create([Microsoft.Identity.Client.AppConfig.ManagedIdentityId]::WithUserAssignedClientId($ClientId))
    }
    else {
        # used by authorizationCode & Device code
        Write-Verbose "[$((Get-Date).TimeofDay)] Public application selected"
        $ClientApplicationBuilder = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create($ClientId)
        if ($PSBoundParameters['TenantId']) {
            Write-Verbose "[$((Get-Date).TimeofDay)] Single tenant app used"
            $ClientApplicationBuilder.WithAuthority($AzureCloudInstance,$TenantId) | Out-Null
        }
        else {
            Write-Verbose "[$((Get-Date).TimeofDay)] Multi tenant app used"
            $ClientApplicationBuilder.WithAuthority($AzureCloudInstance,'common') | Out-Null
        }

        if($WAMFlow){
            Write-Verbose "[$((Get-Date).TimeofDay)] WAM flow selected"
            #Never succeed to make WAM working straight on pwsh. The method WithBroker does not work.
            if($TenantId){
                Write-Verbose "[$((Get-Date).TimeofDay)] Single tenant app used"
                if($extraScopesToConsent){
                    $WAMToken = Get-WAMToken -ClientId $ClientId -RedirectUri $RedirectUri -TenantId $TenantId -AzureCloudInstance $AzureCloudInstance -Scopes $Scopes -extraScopesToConsent $ExtraScopesToConsent
                }
                else{
                    $WAMToken = Get-WAMToken -ClientId $ClientId -RedirectUri $RedirectUri -TenantId $TenantId -AzureCloudInstance $AzureCloudInstance -Scopes $Scopes
                }
            }
            else{
                # Will use the common endpoint
                Write-Verbose "[$((Get-Date).TimeofDay)] Multi tenant app used"
                if($extraScopesToConsent){
                    $WAMToken = Get-WAMToken -ClientId $ClientId -RedirectUri $RedirectUri -AzureCloudInstance $AzureCloudInstance -Scopes $Scopes -extraScopesToConsent $ExtraScopesToConsent
                }
                else{
                    $WAMToken = Get-WAMToken -ClientId $ClientId -RedirectUri $RedirectUri -AzureCloudInstance $AzureCloudInstance -Scopes $Scopes
                }
            }

            return $WAMToken
            #https://devblogs.microsoft.com/identity/improved-windows-broker-support-with-msal-net/
            #$ClientApplicationBuilder.WithDefaultRedirectUri()
            #$ClientApplicationBuilder.WithParentActivityOrWindow($([Win32.Interop]::GetConsoleOrTerminalWindow()))
            #$ClientApplicationBuilder.WithBroker([Microsoft.Identity.Client.BrokerOptions]::new('Windows'))
            #[Microsoft.Identity.Client.Desktop.WamExtension]::WithWindowsBroker($ClientApplicationBuilder, $AuthenticationBroker)
            #[IntPtr] $ParentWindow = [System.Diagnostics.Process]::GetCurrentProcess().MainWindowHandle
            #if ($ParentWindow -eq [System.IntPtr]::Zero -and [System.Environment]::OSVersion.Platform -eq 'Win32NT') {
            #$Win32Process = Get-CimInstance Win32_Process -Filter ("ProcessId = '{0}'" -f [System.Diagnostics.Process]::GetCurrentProcess().Id) -Verbose:$false
            #    $ParentWindow = (Get-Process -Id $Win32Process.ParentProcessId).MainWindowHandle
            #}
            #if ($ParentWindow -ne [System.IntPtr]::Zero) { [void] $ClientApplicationBuilder.WithParentActivityOrWindow($ParentWindow) }
            #$Handle = [Win32.Interop]::GetConsoleOrTerminalWindow
            #$ClientApplicationBuilder.WithParentActivityOrWindow()
            #$brokerOption = [Microsoft.Identity.Client.BrokerOptions]::new('Windows')
            #$brokerOption.ListOperatingSystemAccounts = $true
            #$ClientApplicationBuilder.WithBroker($brokerOption)
           #[Microsoft.Identity.Client.Broker.BrokerExtension]::WithBroker($ClientApplicationBuilder,$brokerOption)

            #throw "Not implemented for now"
        }
        else{
            $ClientApplicationBuilder.WithRedirectUri($RedirectUri) | Out-Null
        }
    }

    $ClientApplication = $ClientApplicationBuilder.Build()

    If ($PSBoundParameters[@('ClientCredentialFlowWithSecret','ClientCredentialFlowWithCertificate','FederatedCredentialFlowWithAssertion')]) {
        #Client credential flow no user cache so no silent
        $AquireTokenParameters = $ClientApplication.AcquireTokenForClient($Scopes)
        $ClientApplication.AcquireTokenForClien
    }
    elseif($PSBoundParameters[@('SystemManagedIdentity','UserManagedIdentity')]){
        $AquireTokenParameters = $ClientApplication.AcquireTokenForManagedIdentity($Scopes)
    }
    elseif($PSBoundParameters[@('OnBehalfFlowWithCertificate','OnBehalfFlowWithSecret')]){
        $AquireTokenParameters = $ClientApplication.AcquireTokenOnBehalfOf($Scopes, [Microsoft.Identity.Client.UserAssertion]::new($UserAssertion))
    }
    else{
        try{

            $T = $PublicClientApplications | Where-Object { $_.ClientId -eq $ClientId -and $_.AppConfig.RedirectUri -eq $RedirectUri} | Select-Object -Last 1
            if($null -eq $T){
                $PublicClientApplications.Add($ClientApplication)
            }
            else{
                $ClientApplication = $T
            }

            [Microsoft.Identity.Client.IAccount]$Account = $ClientApplication.GetAccountsAsync().GetAwaiter().GetResult() | Select-Object -First 1
            if($null -eq $Account){
                throw
            }else{
                $Account
            }
            Write-Verbose "[$((Get-Date).TimeofDay)] Acquire token silently"
            $AquireTokenParameters = $ClientApplication.AcquireTokenSilent($Scopes, $Account)
        }
        catch{
            if($DeviceCodeFlow){
                Write-Verbose "[$((Get-Date).TimeofDay)] Acquire token with device code"
                $AquireTokenParameters = $ClientApplication.AcquireTokenWithDeviceCode($Scopes, [DeviceCodeHelper]::GetDeviceCodeResultCallback())
            }
            else{
                Write-Verbose "[$((Get-Date).TimeofDay)] Acquire token interactively"
                $AquireTokenParameters = $ClientApplication.AcquireTokenInteractive($Scopes)
                if($extraScopesToConsent){
                    $AquireTokenParameters.WithExtraScopesToConsent($extraScopesToConsent)
                }
            }

        }
    }

    # Do the async call to get a token
    $Timeout = New-TimeSpan -Minutes 2
    $tokenSource = New-Object System.Threading.CancellationTokenSource
    try {
        #$AuthenticationResult = $AquireTokenParameters.ExecuteAsync().GetAwaiter().GetResult()
        $taskAuthenticationResult = $AquireTokenParameters.ExecuteAsync($tokenSource.Token)
        try {
            $endTime = [datetime]::Now.Add($Timeout)
            while (!$taskAuthenticationResult.IsCompleted) {
                if ($Timeout -eq [timespan]::Zero -or [datetime]::Now -lt $endTime) {
                    Start-Sleep -Seconds 1
                }
                else {
                    $tokenSource.Cancel()
                    $taskAuthenticationResult.Wait()
                    #try { $taskAuthenticationResult.Wait() }
                    #catch { }
                    Write-Error -Exception (New-Object System.TimeoutException) -Category ([System.Management.Automation.ErrorCategory]::OperationTimeout) -CategoryActivity $MyInvocation.MyCommand -ErrorId 'GetMsalTokenFailureOperationTimeout' -TargetObject $AquireTokenParameters -ErrorAction Stop
                }
            }
        }
        finally {
            if (!$taskAuthenticationResult.IsCompleted) {
                Write-Warning 'Canceling Token Acquisition for Application with ClientId [{0}]' -f $ClientApplication.ClientId
                $tokenSource.Cancel()
            }
            $tokenSource.Dispose()
        }

        ## Parse task results
        if ($taskAuthenticationResult.IsFaulted) {
            Write-Error -Exception $taskAuthenticationResult.Exception -Category ([System.Management.Automation.ErrorCategory]::AuthenticationError) -CategoryActivity $MyInvocation.MyCommand -ErrorId 'GetMsalTokenFailureAuthenticationError' -TargetObject $AquireTokenParameters -ErrorAction Stop
        }
        if ($taskAuthenticationResult.IsCanceled) {
            Write-Error -Exception (New-Object System.Threading.Tasks.TaskCanceledException $taskAuthenticationResult) -Category ([System.Management.Automation.ErrorCategory]::OperationStopped) -CategoryActivity $MyInvocation.MyCommand -ErrorId 'GetMsalTokenFailureOperationStopped' -TargetObject $AquireTokenParameters -ErrorAction Stop
        }
        else {
            $AuthenticationResult = $taskAuthenticationResult.Result
        }
    }
    catch {
        Write-Error -Exception ($_.Exception) -Category ([System.Management.Automation.ErrorCategory]::AuthenticationError) -CategoryActivity $MyInvocation.MyCommand -ErrorId 'GetMsalTokenFailureAuthenticationError' -TargetObject $AquireTokenParameters -ErrorAction Stop
    }

    # Return access token + Id token
    $AuthenticationResult
}
