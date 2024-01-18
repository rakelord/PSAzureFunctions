Function Connect-GraphAPI {
    param(
        [parameter(mandatory)]
        $AzureTenantID,
        [parameter(mandatory)]
        $ApplicationID,
        [parameter(mandatory)]
        $APISecret,
        [parameter(mandatory)]
        [ValidateSet("True","False")]
        $LogToFile
    )
    $Body = @{
        Grant_Type    = "client_credentials"
        Scope         = "https://graph.microsoft.com/.default"
        client_Id     = "$ApplicationID"
        Client_Secret = "$APISecret"
    }

    $OAUTH2Link = "https://login.microsoftonline.com/$AzureTenantID/oauth2/v2.0/token"

    Write-Log -Message "Connecting to Azure Graph API" -Active $LogToFile
    $GraphAPIToken = Invoke-RestMethod -Uri "$OAUTH2Link" -Method POST -Body $Body

    $azureGraphAuthenticationHeader = @{ Authorization = "$($GraphAPIToken.token_type) $($GraphAPIToken.access_token)" }

    $global:AzureGraphAPIAuthenticated = $false
    if ($GraphAPIToken.access_token){
        $global:AzureGraphAPIAuthenticated = $true
        Write-Log -Message "Azure Graph API Authenticated: $AzureGraphAPIAuthenticated" -Active $LogToFile
        Write-Host "Azure Graph API Authenticated: $AzureGraphAPIAuthenticated`nUse Header Connection Variable = "+'$azureGraphAuthenticationHeader'
        $global:azureGraphAuthenticationHeader = $azureGraphAuthenticationHeader
        return ""
    }
    Write-Log -Message "Azure Graph API Authenticated: $AzureGraphAPIAuthenticated" -Active $LogToFile
    Write-Host "Azure Graph API Authenticated: $AzureGraphAPIAuthenticated"
    return $false
}

function Find-AzureGraphAPIConnection {
    if (!$AzureGraphAPIAuthenticated){
        Write-Warning "Azure Graph API is not authenticated, you need to run Connect-GraphAPI and make sure you put in the correct credentials!"
        return $false
    }
    return $true
}

Function Get-EndpointManagerDevices {
    param(
        [parameter(mandatory)]
        [ValidateSet("True","False")]
        $LogToFile,
        [switch]
        $AsHashTable
    )

    if (Find-AzureGraphAPIConnection){
        $Uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"
        $EndpointDevices = @()
        do {
            $Results = Invoke-TryCatchLog -InfoLog "Retrieving 1000 Endpoint devices" -LogToFile $LogToFile -ScriptBlock {
                Invoke-RestMethod -Headers $azureGraphAuthenticationHeader -Uri $Uri -UseBasicParsing -Method "GET" -ContentType "application/json"
            }
            if ($Results.value) {
                $EndpointDevices += $Results.value
            }
            else {
                $EndpointDevices += $Results
            }
            $uri = $Results.'@odata.nextlink'
        } until (!($uri))

        # sort devices by lastSyncDateTime to fix duplicate issues from Endpoint AND give all devices a device_type with either 'Mobile phone' or 'Computer'
        $EndpointDevices = $EndpointDevices | Sort-Object -Property lastSyncDateTime | Select-Object *,@{
            l='device_type';e={
                if ($_.imei -AND $_.operatingSystem -ne 'Windows'){
                    return "Mobile phone"
                }
                return "Computer"
            }
        }
        
        # Faster filtering if HashTable is used, if you can reference the serialnumber when looking for device in Object list.
        $HashTable = @{}
        foreach ($Device in $uniqueDevices){
            $HashTable[$Device.serialNumber] = $Device
        }
        if ($AsHashTable) { return $HashTable }

        $deviceList = @()
        foreach ($Device in $uniqueDevices.Keys) {
            $deviceList += $HashTable[$Device]
        }
        return $deviceList
    }
}

Export-ModuleMember -Function * -Alias *