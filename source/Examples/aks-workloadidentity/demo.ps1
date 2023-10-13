#################
# Demo Workload identity where we use credential federation
#################

Create first your Kubernetes (managed or not)

<#
https://azure.github.io/azure-workload-identity/docs/introduction.html
#>

<#
Explain the Helm addition at the beginning
https://azure.github.io/azure-workload-identity/docs/installation/mutating-admission-webhook.html#helm-3-recommended
#>

Create your dedicated app registration that will represent your pod(s)

<#
App reg config:
No authentication
federated credential
  kubernetes
  <cluster issuer url>
    # Output the OIDC issuer URL
    az aks show --resource-group <resource_group> --name <cluster_name> --query "oidcIssuerProfile.issuerUrl" -otsv
  namespace
    wip
  Service account
    workload-identity-sa
  Audience
    api://AzureADTokenExchange
  No exposed api
#>

#IMPORTANT: Add your values here
$RG = ''
$ACRName = ''
$ACRPassword = ""
$KubeClustername = ""
$TenantId = ''

#Get current cluster info
kubectl cluster-info dump -o json

# Takes time to be up and running (explain later)
helm repo add azure-workload-identity https://azure.github.io/azure-workload-identity/charts
helm repo update
helm install workload-identity-webhook azure-workload-identity/workload-identity-webhook `
   --namespace azure-workload-identity-system `
   --create-namespace `
   --set azureTenantID=$TenantId

#Enable the oidc url
az aks update -g $RG -n $KubeClustername --enable-oidc-issuer

#Show OIDC endpoint url (required in the app registration Cluster issuer URL)
az aks show -n $KubeClustername -g $RG --query "oidcIssuerProfile.issuerUrl" -otsv

# Create wip namespace
kubectl create namespace wip

# Create service account with annotation related to the attached Azure AD app c211bd26-259d-4ebc-bdb9-6c8c45a7a88f in this case
kubectl apply -f .\sa-aad.yaml

#wait for workload identity to start
kubectl get pods -A

# Build container and put it in acr (done already)
az acr build --image "msalwipdemo:latest" -g $RG --registry $ACRName . --file ..\dockerfile

#Declare ACR secret in kubernetes
# IMPORTANT: Check password

kubectl create secret docker-registry acr-secret -n wip --docker-server="$ACRName.azurecr.io" --docker-username=$ACRName --docker-password=$ACRPassword

# Deploy pod that will use ns, sa, Azure acr with stored secret
kubectl apply -f .\pod-deploy-pwsh.yaml

# Gt pod status
kubectl get pods -n wip

# Describe the pod (check injected env variable)
kubectl describe pod demoworkloadidentity -n wip

# Enjoy logs
kubectl logs demoworkloadidentity -n wip

#If you want to look insode the container
kubectl exec demoworkloadidentity -n wip -it -- /bin/pwsh

ls /var/run/secrets/kubernetes.io/serviceaccount/
ls /var/run/secrets/azure/tokens/azure-identity-token

#Delete pod
kubectl delete pod demoworkloadidentity -n wip
