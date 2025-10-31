# Confidential containers on Azure Containers Instances demo 
# Setup Confidential container: attestation and release key
## Overview 

The confidential containers on Azure Containers Instances walks you through the following scenarios using a jupyter notebook.  

* Build a container image and deploy a container group to Azure Container Instances which runs in a trusted execution environment (TEE) with a verifiable security policy 
* Request a remote attestation from the deployed container group. 
* Simulate an error scenario where we fail to launch a container group by changing the container image. 
* Deploy a container group with the updated container image and show how this is reflected in the remote attestation. 
  

## 1. Setup and prerequisites 
The demo requires the following to be available on your machine.
1.	Jupyter notebook : https://jupyter.org/install
2.	Azure CLI : https://learn.microsoft.com/en-us/cli/azure/install-azure-cli
3.	Confcom extension for CLI : https://learn.microsoft.com/en-us/cli/azure/confcom?view=azure-cli-latest 
4.	docker desktop : https://www.docker.com/products/docker-desktop/
5.	git clone git@github.com:ttdung/confidential-sidecar-containers.git
6.	cd confidential-sidecar-containers/shap/cal_shap
7.	https://portal.azure.com/ 
a.	Create a resource group
b.	Create a container registries. E.g: ttdungacr, server: ttdungacr.azurecr.io

## 2. Obtain an Attestation Endpoint
Below are the MAA endpoints (as of April 2025) for the four regions in which Confidential Containers on AKS is currently available.
•	East US: sharedeus.eus.attest.azure.net
•	West US: sharedwus.wus.attest.azure.net
•	North Europe: sharedneu.neu.attest.azure.net
•	West Europe: sharedweu.weu.attest.azure.net

## 3. Azure Key Vault (AKV) and User Managed Identity

$az provider register --namespace Microsoft.KeyVault
$az provider show --namespace Microsoft.KeyVault --query "registrationState"

output: "Registering"

$export VAULT_NAME="<testvaultkhtn>"    
$export REGION="<northeurope>"        
$export RESOURCE_GROUP ="<container_group>"                                    
$az keyvault create -n "$VAULT_NAME" -g "$RESOURCE_GROUP" -l "$REGION" --sku standard
{
  "id": "/subscriptions/63bf8da0-6f25-4075-8fdf-8ec3655d3ede/resourceGroups/container_group/providers/Microsoft.KeyVault/vaults/testvaultkhtn",
  "location": "northeurope",
  "name": "testvaultkhtn",
  "properties": {
    "accessPolicies": [],
    "createMode": null,
    "enablePurgeProtection": null,
    "enableRbacAuthorization": true,
    "enableSoftDelete": true,
    "enabledForDeployment": false,
    "enabledForDiskEncryption": false,
    "enabledForTemplateDeployment": false,
    "hsmPoolResourceId": null,
    "networkAcls": null,
    "privateEndpointConnections": null,
    "provisioningState": "Succeeded",
    "publicNetworkAccess": "Enabled",
    "sku": {
      "family": "A",
      "name": "standard"
    },
    "softDeleteRetentionInDays": 90,
    "tenantId": "40127cd4-45f3-49a3-b05d-315a43a9f033",
    "vaultUri": "https://testvaultkhtn.vault.azure.net/"
  },
  "resourceGroup": "container_group",
  "systemData": {
    "createdAt": "2025-10-28T07:07:37.213000+00:00",
    "createdBy": "ttdung@mso.hcmus.edu.vn",
    "createdByType": "User",
    "lastModifiedAt": "2025-10-28T07:07:37.213000+00:00",
    "lastModifiedBy": "ttdung@mso.hcmus.edu.vn",
    "lastModifiedByType": "User"
  },
  "tags": {},
  "type": "Microsoft.KeyVault/vaults"
}

Error: (Forbidden) Caller is not authorized to perform action on resource.

Fix:
USER_OBJECT_ID="56db1340-ddc1-4cf1-92ae-3f1561943cc0"
VAULT_NAME=testvaultkhtn

az role assignment create \
--role "Key Vault Administrator" \
--assignee-object-id "$USER_OBJECT_ID" \
--assignee-principal-type User \
--scope $(az keyvault show -n $VAULT_NAME --query id -o tsv)

To get USER_OBJECT_ID: goto portal, search “Azure Active Directory” -> find user name, select view profile
 

$az identity create -n "$MANAGED_ID_NAME" -g "$RESOURCE_GROUP" -l "$REGION"
Resource provider 'Microsoft.ManagedIdentity' used by this operation is not registered. We are registering for you.
Registration succeeded.
{
  "clientId": "efa24a49-f512-481d-8e0c-5f17c7c2258f",
  "id": "/subscriptions/63bf8da0-6f25-4075-8fdf-8ec3655d3ede/resourcegroups/container_group/providers/Microsoft.ManagedIdentity/userAssignedIdentities/manage_id_name",
  "location": "northeurope",
  "name": "manage_id_name",
  "principalId": "1ec7fd63-0b33-484f-8ee1-f056a9bc5ced",
  "resourceGroup": "container_group",
  "systemData": null,
  "tags": {},
  "tenantId": "40127cd4-45f3-49a3-b05d-315a43a9f033",
  "type": "Microsoft.ManagedIdentity/userAssignedIdentities"
}

$az identity show \
  --name "$MANAGED_ID_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --query principalId -o tsv

1ec7fd63-0b33-484f-8ee1-f056a9bc5ced

$export PRINCIPAL_ID="1ec7fd63-0b33-484f-8ee1-f056a9bc5ced"
$export SUBSCRIPTION_ID=$(az account show --query id -o tsv)
$az role assignment create \
--assignee-object-id "$PRINCIPAL_ID" \
--role "Key Vault Crypto Service Release User" \
--scope "subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.KeyVault/vaults/$VAULT_NAME" \
--assignee-principal-type ServicePrincipal
{
  "condition": null,
  "conditionVersion": null,
  "createdBy": null,
  "createdOn": "2025-10-28T07:38:05.583399+00:00",
  "delegatedManagedIdentityResourceId": null,
  "description": null,
  "id": "/subscriptions/63bf8da0-6f25-4075-8fdf-8ec3655d3ede/resourceGroups/container_group/providers/Microsoft.KeyVault/vaults/testvaultkhtn/providers/Microsoft.Authorization/roleAssignments/9436a262-d065-4f02-a80f-ac66fc001c3b",
  "name": "9436a262-d065-4f02-a80f-ac66fc001c3b",
  "principalId": "1ec7fd63-0b33-484f-8ee1-f056a9bc5ced",
  "principalType": "ServicePrincipal",
  "resourceGroup": "container_group",
  "roleDefinitionId": "/subscriptions/63bf8da0-6f25-4075-8fdf-8ec3655d3ede/providers/Microsoft.Authorization/roleDefinitions/08bbd89e-9f13-488c-ac41-acfcb10c90ab",
  "scope": "/subscriptions/63bf8da0-6f25-4075-8fdf-8ec3655d3ede/resourceGroups/container_group/providers/Microsoft.KeyVault/vaults/testvaultkhtn",
  "type": "Microsoft.Authorization/roleAssignments",
  "updatedBy": "56db1340-ddc1-4cf1-92ae-3f1561943cc0",
  "updatedOn": "2025-10-28T07:38:06.647004+00:00"
}

Check User Managed Identity
If you already have a user-assigned managed identity with the appropriate access permissions:
$az identity list -g "$RESOURCE_GROUP"
[
  {
    "clientId": "efa24a49-f512-481d-8e0c-5f17c7c2258f",
    "id": "/subscriptions/63bf8da0-6f25-4075-8fdf-8ec3655d3ede/resourcegroups/container_group/providers/Microsoft.ManagedIdentity/userAssignedIdentities/manage_id_name",
    "location": "northeurope",
    "name": "manage_id_name",
    "principalId": "1ec7fd63-0b33-484f-8ee1-f056a9bc5ced",
    "resourceGroup": "container_group",
    "systemData": null,
    "tags": {},
    "tenantId": "40127cd4-45f3-49a3-b05d-315a43a9f033",
    "type": "Microsoft.ManagedIdentity/userAssignedIdentities"
  }
]

## 4. Obtain the AAD token
 Use the appropriate command to obtain the AAD token with permission to the AKV or mHSM:
For AKV
az account get-access-token --resource "https://<vaultname>.vault.azure.net" --query "accessToken" --output tsv
For mHSM
az account get-access-token --resource "https://<vaultname>.managedhsm.azure.net" --query "accessToken" --output tsv

$az account get-access-token --resource "https://testvaultkhtn.vault.azure.net" --query "accessToken" --output tsv
thisissameple-output-tokeMUh3U1FQTkZvMG13WFRGYVE2bndNem16cU0taWdocEhvOGtQd0w1NlFKTXNBUWhVQUEuIiwic2NwIjoidXNlcl9pbXBlcnNvbmF0aW9uIiwic2lkIjoiZjYwMzgxMDAtNmUwYy00MzYwLWFhMDctZTNlOWM3MWY3ZWMzIiwic3ViIjoiQzlJaFM0dVVkV0dOaVFGcExTOGhDWHdVWE9VRE05ZXFOT0JJS1Z5YUhsdyIsInRpZCI6IjQwMTI3Y2Q0LTQ1ZjMtNDlhMy1iMDVkLTMxNWE0M2E5ZjAzMyIsInVuaXF1ZV9uYW1lIjoidHRkdW5nQG1zby5oY211cy5lZHUudm4iLCJ1cG4

Replace the above with the accessToken from the previous command's output:
•	AAD token at “bearer_token” in importkeyconfig.json
"akv": {
            "endpoint": "<key-vault-endpoint>",
            "api_version": "api-version=7.4",
            "bearer_token": "",
}

## 5. Fill in Key Information

After setting up an Azure Key Vault resource:
•	Within importkeyconfig.json:
o	Add a key name to be created and imported into the key vault, under key.kid.
o	Replace the key-vault-endpoint (WITHOUT https://) in the format: <VAULT_NAME>.vault.azure.net (e.g. testvaultkhtn.vault.azure.net)
•	Additionally, fill in (or remove) these optional fields in the importkeyconfig.json file:
o	 Key type: RSA-HSM or oct-HSM
	Supported key types for each vault are listed here.
•	For the template.json:
o	Run the following command to get the full managed identity, and replace full-path-to-managed-identity-with-right-permissions-to-key-vault with the output:

$az identity show -n "$MANAGED_ID_NAME" -g "$RESOURCE_GROUP" --query id -o tsv

output:
/subscriptions/63bf8da0-6f25-4075-8fdf-8ec3655d3ede/resourcegroups/container_group/providers/Microsoft.ManagedIdentity/userAssignedIdentities/manage_id_name

## 6. Build and upload CalculateShap image
o	Start Docker desktop in the background
$az acr login -n ttdungacr
Login Succeeded
$cd confidential-sidecar-containers/shap/cal_shap
$python3 build_upload_shap_image.py
Building image: ttdungacr.azurecr.io/cacidemo:7 from ./
--- Docker Build SUCCESSFUL ---


Pushing image: ttdungacr.azurecr.io/cacidemo:7
--- Docker Push SUCCESSFUL ---
The push refers to repository [ttdungacr.azurecr.io/cacidemo]

Error:
--- Docker Push FAILED ---
error from registry: authentication required, visit https://aka.ms/acr/authorization for more information. CorrelationId: d3de1e19-9899-43c5-ac0b-605ff7806981

Fix: $az acr login -n ttdungacr
To check image upload successfully
$az acr repository show-tags --name ttdungacr --repository cacidemo -o table

To delete
$az acr repository delete --name ttdungacr --image cacidemo:2.1 --yes
## 7. Generate Security Policy
At this point, the template.json file should be filled out except for the ccepolicy field.
After installing the Azure confcom CLI extension:
•	 Run the following command to generate the security policy and include the --debug-mode option so that the policy allows users to shell into the container. Do not include the --debug-mode for production.

az confcom acipolicygen -a "template.json" --debug-mode

•	 Accept the prompt to automatically populate the cce policy field in template.json
This should output the SHA-256 digest of the security policy.
o	 Copy it and replace the hash-digest-of-the-security-policy string in importkeyconfig.json (in the below pic, copy the SHA-256 digest at bottom).
 

## 8. Import Keys into AKV/mHSM
Use the following command from the confidential-sidecar-containers/shap/cal_shap directory:

$go run "../../../tools/importkey/main.go" -c "importkeyconfig.json" -out 


If get error: {"error":{"code":"Unauthorized","message":"[TokenExpired] Error validating token: 'S2S12086'."}}: http response status equal to 401 Unauthorized

Fix:
$az account get-access-token --resource "https://testvaultkhtn.vault.azure.net" --query "accessToken" --output tsv

Copy output to “bearer_token” in importkeyconfig.json

To check the key imported successfully

$az keyvault key list --vault-name "$VAULT_NAME" -o table

Kid                                               Name
------------------------------------------------  ------
https://testvaultkhtn.vault.azure.net/keys/mykey  mykey

To delete key
az keyvault key delete \                                                               
  --vault-name "$VAULT_NAME" \
  --name "mykey"
## 9. Deployment
You can deploy using the CLI or Azure Portal:
CLI:
•	 Run:
az deployment group create -g "$RESOURCE_GROUP" --template-file "template.json"


Error:
CompletedProcess(args='az deployment group create -g container_group -f ./sum/template.json', returncode=1, stdout=b'', stderr=b'ERROR: {"status":"Failed","error":{"code":"DeploymentFailed","target":"/subscriptions/63bf8da0-6f25-4075-8fdf-8ec3655d3ede/resourceGroups/container_group/providers/Microsoft.Resources/deployments/template","message":"At least one resource deployment operation failed. Please list deployment operations for details. Please see https://aka.ms/arm-deployment-operations for usage details.","details":[{"code":"ResourceDeploymentFailure","target":"/subscriptions/63bf8da0-6f25-4075-8fdf-8ec3655d3ede/resourceGroups/container_group/providers/Microsoft.ContainerInstance/containerGroups/aci-demo-sum","message":"The resource write operation failed to complete successfully, because it reached terminal provisioning state \'Failed\'.","details":[{"message":"pulling image \\"mcr.microsoft.com/aci/skr@sha256:a4127a1e5dd857a5217f12eeb90da1b5555a0cd3591de0a5ffdc926394586587\\";Successfully pulled image \\"mcr.microsoft.com/aci/skr@sha256:a4127a1e5dd857a5217f12eeb90da1b5555a0cd3591de0a5ffdc926394586587\\";Started container;pulling image \\"ttdungacr.azurecr.io/cacidemo@sha256:e0802935c9d86b502c33b0e964abee45693663863436b615d8afee9b06f60985\\";Successfully pulled image \\"ttdungacr.azurecr.io/cacidemo@sha256:e0802935c9d86b502c33b0e964abee45693663863436b615d8afee9b06f60985\\";Error: Failed to start container test-sum, Error response: to create containerd task: failed to create shim task: failed to mount container storage: failed to add LCOW layer: failed to add SCSI layer: mount scsi controller 0 lun 5 at /run/mounts/scsi/m4: guest RPC failure: mounting scsi device controller 0 lun 5 onto /run/mounts/scsi/m4 denied by policy: policyDecision< >policyDecision: unknown;failed to create containerd task: failed to create shim task: failed to mount container storage: failed to add LCOW layer: failed to add SCSI layer: mount scsi controller 0 lun 5 at /run/mounts/scsi/m4: guest RPC failure: mounting scsi device controller 0 lun 5 onto /run/mounts/scsi/m4 denied by policy: {\\"decision\\":\\"deny\\",\\"input\\":{\\"deviceHash\\":\\"1e58f797264749d1616310f8b22389e7f9efd3bccf7639516237f78d03a25d26\\",\\"mountPathRegex\\":\\"/run/mounts/scsi/m[0-9]+\\",\\"rule\\":\\"mount_device\\",\\"target\\":\\"/run/mounts/scsi/m4\\"},\\"reason\\":{\\"errors\\":[\\"deviceHash not found\\"]}};The container group provisioning has failed. Refer to \'DeploymentFailedReason\' event for more details."}]}]}}\n')

Fix:
Rootcasue is the cee_policy or at least one image does not work properly. Almost case is due to cce_policy:
In template.json, remove "ccePolicy": "cGFja2FnZSBwb2…”
Then re-create the cce_policy: $az confcom acipolicygen -a "template.json" --debug-mode
If the cce_policy is correct, checking the images can start on your local, even they works properly in your local, review the code. e.g. do NOT use abort() in your python code.

Error:
$az deployment group create -g "$RESOURCE_GROUP" --template-file "template.json"
{"status":"Failed","error":{"code":"DeploymentFailed","target":"/subscriptions/63bf8da0-6f25-4075-8fdf-8ec3655d3ede/resourceGroups/container_group/providers/Microsoft.Resources/deployments/aci-arm-template","message":"At least one resource deployment operation failed. Please list deployment operations for details. Please see https://aka.ms/arm-deployment-operations for usage details.","details":[{"code":"InvalidImageRegistryServer","message":"The server '<registry-name>' in the 'imageRegistryCredentials' of container group 'aciSKRSidecarTest' is invalid. It should be a valid host name without protocol."}]}}

Fix:
Search imageRegistryCredentials in template.json and remove this tag

## 10. Verify the deployed container
-	Start jupyter lab
-	Open  /confidential-sidecar-containers/shap/caci-shap-demo.ipynb
-	Update: 
o	registry_name = 'ttdungacr.azurecr.io' # e.g. ttdungacr.azurecr.io  or docker.io/ttdungcr
o	attestation_endpoint = 'sharedneu.neu.attest.azure.net'
o	public_ip_address ='' // address of the deployed container


NOTE:
-	More detailed readme. https://github.com/microsoft/confidential-sidecar-containers/blob/main/examples/skr/aci/README.md

-	To change the key: have to do steps: 5,6,7
-	To update image:
1.	Build image: python3 build_upload_shap_image.py   
az acr repository show-tags --name ttdungacr --repository cacidemo -o table
az acr repository delete --name ttdungacr --image cacidemo:9 --yes
2.	Update template.json -> rebuild cce_policy: az confcom acipolicygen -a "template.json" --debug-mode
Copy SHA256-code into importkeyconfig.json
Copy cce_policy into template.json
3.	Create new key: go run "../../tools/importkey/main.go" -c "importkeyconfig.json" -out
az keyvault key list --vault-name "$VAULT_NAME" -o table 
az keyvault key delete --vault-name "$VAULT_NAME" --name "mykey-v2"
4.	Deploy containers:  az deployment group create -g "$RESOURCE_GROUP" --template-file "template.json"

 
Reference:

https://github.com/microsoft/confidential-sidecar-containers
https://github.com/Azure-Samples/confidential-container-samples
https://learn.microsoft.com/en-us/azure/attestation/overview
