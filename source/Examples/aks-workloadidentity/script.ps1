import-module PSMSALNet

while ($true) {

    Write-Host '###############################'
    Write-Host 'Working on workload identity demo'
    Write-Host '###############################'
    Write-Host ''

    #Read Kubernetes Service account token from mounted volume
    Write-Host "    Read Kubernetes projected service account token"
    $KubeSaToken = Get-Content -Path '/var/run/secrets/azure/tokens/azure-identity-token'
    if ($null -eq $KubeSaToken) {
        Throw 'Kubernetes Service Account token is not exposed as volume'
    }
    else {
        Write-Host '        Kubernetes token exposed through volume:'
        Write-host "            $KubeSaToken"
    }

    Write-Host ''
    Write-Host "    Let's exchange this Kubernetes token to Azure AD"
    Write-Host ''

    # Contact Entra with federated credential
    Get-EntraToken -FederatedCredentialFlowWithAssertion -UserAssertion $KubeSaToken -ClientId $([Environment]::GetEnvironmentVariable('AZURE_CLIENT_ID')) -TenantId $([Environment]::GetEnvironmentVariable('AZURE_TENANT_ID')) -Resource GraphAPI

    Start-Sleep -Seconds 10
}
