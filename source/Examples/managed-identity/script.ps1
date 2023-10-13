import-module PSMSALNet

while($true){
    Get-EntraToken -SystemManagedIdentity -Resource GraphAPI
    Start-Sleep -Seconds 30
}
