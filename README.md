Powershell API functions for Azure (wrappers for better data)
<br><br>
This repository will keep updating as the functions I use internally at work start growing.<br>
<br>
At this moment it is mostly used for Synchronization activities to retrieve data and put it somewhere else, but when we start making changes to objects this will be further updated.
<br><br>
If you are looking a function that is missing please send me a message/comment and I will add it to the repository!

# Required modules
* PSLoggingFunctions (https://github.com/rakelord/PSLoggingFunctions)

# Getting started
## Download this module folder and all Required Powershell Modules and place them in your modules folder<br>
Windows default - "C:\Program Files\WindowsPowerShell\Modules"

# Functions examples
## Connect to the API
First you are going to have to create a API Token which is explained in Microsofts official RestAPI documentation.
<br><br>
- LogToFile parameter is connected to the PSLoggingFunctions module and is used for easy logging.
```
 Connect-GraphAPI -AzureTenantID "<TENANTID>" -ApplicationID "<APPLICATIONID>" -APISecret "<APISECRET>" -LogToFile "<True/False>"
```
You will retrieve a global variable in your script called '$azureGraphAuthenticationHeader' the variable can be used with your own Invoke-RestMethod commands if needed, otherwise you can use the module functions which have this variable implemented already.

## Retrieve Endpoint Manager Objects
These functions are based on that the Connect-GraphAPI has been run and is authenticated, otherwise you will receive an error than you need to connect.
```
# This creates a Powershell HashTable Object
Get-EndpointManagerDevices -AsHashTable -LogToFile "<True/False>"

# This gives you a normal Powershell Object
Get-EndpointManagerDevices -LogToFile "<True/False>"
```