Function Connect-GraphAPI {
    param(
        [parameter(mandatory)]
        $AzureTenantID,
        [parameter(mandatory)]
        $ApplicationID,
        $APISecret,
        $CertThumbprint,
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

    $OAUTH2Url = "https://login.microsoftonline.com/$AzureTenantID/oauth2/v2.0/token"

    $Cert = Get-Certificate -thumbPrint $CertThumbprint -storeName "My"

    Write-Log -Message "Connecting to Azure Graph API" -Active $LogToFile
    
    if ($Cert){ # Certificate
        $binaryCertificateFingerprint = Convert-HexStringToByteArray($Cert.Thumbprint)
        $base64EncodedFingerprint = [System.Convert]::ToBase64String($binaryCertificateFingerprint)

        $JWT_Header = @{
            alg = "RS256"
            x5t = $base64EncodedFingerprint
            typ = "JWT"
        } | ConvertTo-Json

        $now = (Get-Date).ToUniversalTime()
        $createDate = (New-TimeSpan -Start 1970-01-01 -End ($now).DateTime).TotalSeconds
        $expiryDate = (New-TimeSpan -Start 1970-01-01 -End ($now).AddMinutes(60).DateTime).TotalSeconds
        $JWT_Payload = @{
            iss = $ApplicationID
            sub = $ApplicationID
            aud = $OAUTH2Url
            iat = $createDate
            nbf = $createDate
            exp = $expiryDate
            jti = (New-Guid).Guid
        } | ConvertTo-Json

        $JWT_Token = New-Jwt -Cert $Cert -PayloadJson $JWT_Payload -Header $JWT_Header

        $Form = @{
            grant_type              = "client_credentials"
            client_assertion_type   = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            client_id               = $ApplicationID
            scope                   = "https://graph.microsoft.com/.default"
            client_assertion        = $JWT_Token
        }

        $Headers = @{
            "Content-Type" = "application/x-www-form-urlencoded;charset=UTF-8"
        }
        
        $GraphAPIToken = Invoke-RestMethod -Method POST -Uri $OAUTH2Url -Body $Form -Headers $Headers
        $azureGraphAuthenticationHeader = @{ Authorization = "$($GraphAPIToken.token_type) $($GraphAPIToken.access_token)" }
    }
    else { # Secret
        $GraphAPIToken = Invoke-RestMethod -Uri "$OAUTH2Url" -Method POST -Body $Body
        $azureGraphAuthenticationHeader = @{ Authorization = "$($GraphAPIToken.token_type) $($GraphAPIToken.access_token)" }
    }

    # Verify connection
    $global:AzureGraphAPIAuthenticated = $false
    if ($GraphAPIToken.access_token){
        $global:AzureGraphAPIAuthenticated = $true
        Write-Log -Message "Azure Graph API Authenticated: $AzureGraphAPIAuthenticated" -Active $LogToFile
        Write-Host "Azure Graph API Authenticated: $AzureGraphAPIAuthenticated"
        Write-Host "Use Header Connection Variable ="'$azureGraphAuthenticationHeader'
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

function Convert-HexStringToByteArray {
    param (
        [string]$hex
    )

    $byteArray = [byte[]]::new($hex.length / 2)
    for ($i = 0; $i -lt $hex.length; $i += 2) {
        $byteArray[$i / 2] = [byte]::Parse($hex.Substring($i, 2), [System.Globalization.NumberStyles]::HexNumber)
    }

    return $byteArray
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
        foreach ($Device in $EndpointDevices){
            $HashTable[$Device.serialNumber] = $Device
        }
        if ($AsHashTable) { return $HashTable }

        $deviceList = @()
        foreach ($Device in $HashTable.Keys) {
            $deviceList += $HashTable[$Device]
        }
        return $deviceList
    }
}

function Get-Certificate {
    Param(
        [parameter(mandatory)]
        $thumbPrint,
        [parameter(mandatory)]
        $storeName
    )
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, "LocalMachine")
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $certificates = $store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $thumbPrint, $false)
    $store.Close()

    return $certificates[0]
}
function ConvertTo-Base64UrlString {
    <#
    .SYNOPSIS
    Base64url encoder.
    
    .DESCRIPTION
    Encodes a string or byte array to base64url-encoded string.
    
    .PARAMETER in
    Specifies the input. Must be string, or byte array.
    
    .INPUTS
    You can pipe the string input to ConvertTo-Base64UrlString.
    
    .OUTPUTS
    ConvertTo-Base64UrlString returns the encoded string by default.
    
    .EXAMPLE
    
    PS Variable:> '{"alg":"RS256","typ":"JWT"}' | ConvertTo-Base64UrlString
    eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9
    
    .LINK
    https://github.com/SP3269/posh-jwt
    .LINK
    https://jwt.io/
    
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]$in
    )
    if ($in -is [string]) {
        return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($in)) -replace '\+','-' -replace '/','_' -replace '='
    }
    elseif ($in -is [byte[]]) {
        return [Convert]::ToBase64String($in) -replace '\+','-' -replace '/','_' -replace '='
    }
    else {
        throw "ConvertTo-Base64UrlString requires string or byte array input, received $($in.GetType())"
    }
}

function New-Jwt {
    <#
    .SYNOPSIS
    Creates a JWT (JSON Web Token).
    
    .DESCRIPTION
    Creates signed JWT given a signing certificate and claims in JSON.
    
    .PARAMETER Payload
    Specifies the claim to sign in JSON. Mandatory string.
    
    .PARAMETER Header
    Specifies a JWT header. Optional. Defaults to '{"alg":"RS256","typ":"JWT"}'.
    
    .PARAMETER Cert
    Specifies the signing certificate of type System.Security.Cryptography.X509Certificates.X509Certificate2. Must be specified and contain the private key if the algorithm in the header is RS256.
    
    .PARAMETER Secret
    Specifies the HMAC secret. Can be byte array, or a string, which will be converted to bytes. Must be specified if the algorithm in the header is HS256.
    
    .INPUTS
    You can pipe a string object (the JSON payload) to New-Jwt.
    
    .OUTPUTS
    System.String. New-Jwt returns a string with the signed JWT.
    
    .EXAMPLE
    PS Variable:\> $cert = (Get-ChildItem Cert:\CurrentUser\My)[1]
    
    PS Variable:\> New-Jwt -Cert $cert -PayloadJson '{"token1":"value1","token2":"value2"}'
    eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbjEiOiJ2YWx1ZTEiLCJ0b2tlbjIiOiJ2YWx1ZTIifQ.Kd12ryF7Uuk9Y1UWsqdSk6cXNoYZBf9GBoqcEz7R5e4ve1Kyo0WmSr-q4XEjabcbaG0hHJyNGhLDMq6BaIm-hu8ehKgDkvLXPCh15j9AzabQB4vuvSXSWV3MQO7v4Ysm7_sGJQjrmpiwRoufFePcurc94anLNk0GNkTWwG59wY4rHaaHnMXx192KnJojwMR8mK-0_Q6TJ3bK8lTrQqqavnCW9vrKoWoXkqZD_4Qhv2T6vZF7sPkUrgsytgY21xABQuyFrrNLOI1g-EdBa7n1vIyeopM4n6_Uk-ttZp-U9wpi1cgg2pRIWYV5ZT0AwZwy0QyPPx8zjh7EVRpgAKXDAg
    
    .EXAMPLE
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("/mnt/c/PS/JWT/jwt.pfx","jwt")
    
    $now = (Get-Date).ToUniversalTime()
    $createDate = [Math]::Floor([decimal](Get-Date($now) -UFormat "%s"))
    $expiryDate = [Math]::Floor([decimal](Get-Date($now.AddHours(1)) -UFormat "%s"))
    $rawclaims = [Ordered]@{
        iss = "examplecom:apikey:uaqCinPt2Enb"
        iat = $createDate
        exp = $expiryDate
    } | ConvertTo-Json
    
    $jwt = New-Jwt -PayloadJson $rawclaims -Cert $cert
    
    $apiendpoint = "https://api.example.com/api/1.0/systems"
    
    $splat = @{
        Method="GET"
        Uri=$apiendpoint
        ContentType="application/json"
        Headers = @{authorization="bearer $jwt"}
    }
    
    Invoke-WebRequest @splat
    
    .LINK
    https://github.com/SP3269/posh-jwt
    .LINK
    https://jwt.io/
    
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)][string]$Header = '{"alg":"RS256","typ":"JWT"}',
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)][string]$PayloadJson,
        [Parameter(Mandatory=$false)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
        [Parameter(Mandatory=$false)]$Secret # Can be string or byte[] - checks in the code
    )

    Write-Verbose "Payload to sign: $PayloadJson"

    try { $Alg = (ConvertFrom-Json -InputObject $Header -ErrorAction Stop).alg } # Validating that the parameter is actually JSON - if not, generate breaking error
    catch { throw "The supplied JWT header is not JSON: $Header" }
    Write-Verbose "Algorithm: $Alg"

    try { ConvertFrom-Json -InputObject $PayloadJson -ErrorAction Stop | Out-Null } # Validating that the parameter is actually JSON - if not, generate breaking error
    catch { throw "The supplied JWT payload is not JSON: $PayloadJson" }

    $encodedHeader = ConvertTo-Base64UrlString $Header
    $encodedPayload = ConvertTo-Base64UrlString $PayloadJson

    $jwt = $encodedHeader + '.' + $encodedPayload # The first part of the JWT

    $toSign = [System.Text.Encoding]::UTF8.GetBytes($jwt)

    switch($Alg) {
    
        "RS256" {
            if (-not $PSBoundParameters.ContainsKey("Cert")) {
                throw "RS256 requires -Cert parameter of type System.Security.Cryptography.X509Certificates.X509Certificate2"
            }
            Write-Verbose "Signing certificate: $($Cert.Subject)"
            $rsa = $Cert.PrivateKey
            if ($null -eq $rsa) { # Requiring the private key to be present; else cannot sign!
                throw "There's no private key in the supplied certificate - cannot sign" 
            }
            else {
                # Overloads tested with RSACryptoServiceProvider, RSACng, RSAOpenSsl
                try { $sig = ConvertTo-Base64UrlString $rsa.SignData($toSign,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1) }
                catch { throw New-Object System.Exception -ArgumentList ("Signing with SHA256 and Pkcs1 padding failed using private key $($rsa): $_", $_.Exception) }
            }
        }
        "HS256" {
            if (-not ($PSBoundParameters.ContainsKey("Secret"))) {
                throw "HS256 requires -Secret parameter"
            }
            try { 
                $hmacsha256 = New-Object System.Security.Cryptography.HMACSHA256
                if ($Secret -is [byte[]]) {
                    $hmacsha256.Key = $Secret
                }
                elseif ($Secret -is [string]) {
                    $hmacsha256.Key = [System.Text.Encoding]::UTF8.GetBytes($Secret)
                }
                else {
                    throw "Expected Secret parameter as byte array or string, instead got $($Secret.gettype())"
                }                
                $sig = ConvertTo-Base64UrlString $hmacsha256.ComputeHash($toSign)
            }
            catch { throw New-Object System.Exception -ArgumentList ("Signing with HMACSHA256 failed: $_", $_.Exception) }
        }
        "none" {
            $sig = $null
        }
        default {
            throw 'The algorithm is not one of the supported: "RS256", "HS256", "none"'
        }

    }
    
    $jwt = $jwt + '.' + $sig
    return $jwt
}

Export-ModuleMember -Function * -Alias *