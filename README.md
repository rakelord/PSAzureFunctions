Powershell API functions for Azure (wrappers for better data)
<br><br>
This repository will keep updating as the functions I use internally at work start growing.<br>
<br>
At this moment it is mostly used for Synchronization activities to retrieve data and put it somewhere else, but when we start making changes to objects this will be further updated.
<br><br>
If you are looking a function that is missing please send me a message/comment and I will add it to the repository!

# Required modules
* PSLoggingFunctions (https://github.com/rakelord/PSLoggingFunctions)

# Installation
```powershell 
Install-Module -Name PSAzureFunctions
``` 
# Offline Installation
Just run the OfflineInstallation.ps1 as Administrator
PS: You need to download all the files into the same directory and then run the script, they will then be copied to the Users PSModuleDirectory.

## All functions are based on that the Connect-GraphAPI has been run and is authenticated, otherwise you will receive an error than you need to connect.

# Functions examples
## Connect to the API
First you are going to have to create an Azure Application with an API Secret or a Certificate which is explained in Microsofts official RestAPI documentation.
<br><br>
- LogToFile parameter is connected to the PSLoggingFunctions module and is used for easy logging.

```powershell
 Connect-GraphAPI -AzureTenantID "<TENANTID>" -ApplicationID "<APPLICATIONID>" -APISecret "<APISECRET>" -LogToFile "<True/False>"
```
OR
```powershell
 Connect-GraphAPI -AzureTenantID "<TENANTID>" -ApplicationID "<APPLICATIONID>" -CertThumbprint "<CERTIFICATE THUMBPRINT>" -LogToFile "<True/False>"
```
You will retrieve a global variable in your script called '$azureGraphAuthenticationHeader' the variable can be used with your own Invoke-RestMethod commands if needed, otherwise you can use the module functions which have this variable implemented already.

## Retrieve Endpoint Manager Objects
```powershell
# This creates a Powershell HashTable Object with the serialNumber as Key.
# Example $EndpointDevice['COMPUTER-XXXXXX']
Get-EndpointManagerDevices -AsHashTable -LogToFile "<True/False>"

# This gives you a normal Powershell Object
Get-EndpointManagerDevices -LogToFile "<True/False>"
```

## Retrieve Entra User Objects
```powershell
# This creates a Powershell HashTable Object with the ID as Key.
# Example $EntraObject['XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX']
Get-EntraIDUsers -AsHashTable -HashTableKey id -LogToFile $True
# Or if you want userprincipalName as Key
Get-EntraIDUsers -AsHashTable -HashTableKey userprincipalName -LogToFile $True

# This gives you a normal Powershell Object
Get-EntraIDUsers -LogToFile $True

# Use a filter to only retrieve a small amount of data
Get-EntraIDUsers -Filter "startswith(displayName,'Mag')" -LogToFile $False
```