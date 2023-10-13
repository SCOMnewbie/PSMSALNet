$MyRG = ''
$ACRName = ''

az acr update -n $ACRName --admin-enabled true
$acrPassword = az acr credential show -n $ACRName -g $MyRG | ConvertFrom-Json -Depth 99 | % passwords | select -ExpandProperty value -f 1
$Token = az acr login -n $ACRName --expose-token
az acr build --image "aci:latest" -g $MyRG --registry $ACRName "$($PWD.path)" --file "Dockerfile"
