using namespace System.Collections.Generic
using namespace System.Net.Http
using namespace System.Security

#Region Classes

class NSConnection {
    [string]$BaseUrl
    [string]$Token
    [datetime]$TokenExpiration
    [string]$ClientId
    [string]$ClientSecret
    hidden [PSCredential]$Credentials
    hidden [Dictionary[string, object]]$Cache

    NSConnection([string]$baseUrl, [string]$clientId, [string]$clientSecret) {
        $this.BaseUrl = $baseUrl
        $this.ClientId = $clientId
        $this.ClientSecret = $clientSecret
        $this.Cache = [Dictionary[string, object]]::new()
    }

    [void] Connect([PSCredential]$credentials) {
        $this.Credentials = $credentials
        $this.RefreshToken()
    }

    [void] RefreshToken() {
        $tokenUrl = "{0}/ns-api/oauth2/token/?grant_type=password&client_id={1}&client_secret={2}&username={3}&password={4}" -f 
        $this.BaseUrl,
        [Uri]::EscapeDataString($this.ClientId),
        [Uri]::EscapeDataString($this.ClientSecret),
        [Uri]::EscapeDataString($this.Credentials.UserName),
        [Uri]::EscapeDataString($this.Credentials.GetNetworkCredential().Password)

        $response = Invoke-RestMethod -Uri $tokenUrl -Method Post
        $this.Token = $response.access_token
        $this.TokenExpiration = (Get-Date).AddSeconds($response.expires_in)
    }

    [PSCustomObject] InvokeRequest([string]$object, [string]$action, [hashtable]$params) {
        if (-not $this.Token -or $this.TokenExpiration -lt [datetime]::Now) {
            $this.Authenticate()
        }

        # Build the query string
        $queryParams = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        foreach ($key in $params.Keys) {
            $queryParams[$key] = $params[$key]
        }
        $queryParams['object'] = $object
        $queryParams['action'] = $action
        $queryParams['format'] = 'json'

        # Construct the URL with query parameters
        $uri = "$($this.BaseUrl)/ns-api/?" + $queryParams.ToString()

        $headers = @{
            'Authorization' = "Bearer $($this.Token)"
        }

        try {
            Write-Verbose "Requesting URL: $uri"
            $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
            
            if ($response.PSObject.Properties.Name -contains 'code' -and $response.code -ne 200) {
                Write-Warning "API returned error code $($response.code): $($response.msg)"
                if ($response.code -eq 404) {
                    return $null
                }
                throw "API Error: $($response.msg)"
            }

            if ($response.PSObject.Properties.Name -contains 'total') {
                return @{
                    total = [int]$response.total
                    items = $response.items
                }
            }
            
            return $response
        }
        catch {
            Write-Warning "API request failed: $_"
            if ($_.Exception.Response.StatusCode -eq 404) {
                return $null
            }
            throw
        }
    }

    [void] ClearCache() {
        $this.Cache.Clear()
    }
}

class NSBaseObject {
    [PSCustomObject]$RawData

    NSBaseObject([PSCustomObject]$rawData) {
        $this.RawData = $rawData
    }
}

class NSDevice : NSBaseObject {
    [string]$Domain
    [string]$User
    [string]$Mac
    [string]$Model
    [string]$Vendor
    [string]$Extension
    [string]$Suffix
    [string]$FullExtension
    [string]$AOR  # Address of Record (SIP address) - Primary identifier for the device
    
    # Additional subscriber-related fields
    [string]$SubscriberName
    [string]$SubscriberDomain
    [string]$SubscriberEmail
    [string]$AORUser
    [string]$AuthenticationKey
    [string]$SubscriberFullName
    [string]$SubscriberLogin
    [string]$SubscriberScope
    [string]$ServiceCode
    [string]$CallerID911
    [string]$CallProcessingRule
    [string]$Mode
    [string]$UserAgent
    [string]$Hostname
    [string]$AddressIdSource
    [string]$AddressPrettyPrint
    [string]$Contact
    [datetime]$RegistrationTime
    [datetime]$RegistrationExpiresTime


    NSDevice([PSCustomObject]$rawData) : base($rawData) {
        $this.Domain = $rawData.subscriber_domain
        $this.User = $rawData.subscriber_name
        $this.Mac = $rawData.mac
        $this.Model = $rawData.model
        $this.Vendor = $rawData.vendor
        $this.Extension = $rawData.subscriber_name
        $rawData.aor -match '(sip:)(\d+)([a-z]{0,2})?@([\w\.\-]+)' | Out-Null
        if($matches.count -gt 4) {
            $this.FullExtension = $matches[2] + $matches[3]
            $this.Suffix = $matches[3]
        } elseif ($matches.count -gt 3) {
            $this.FullExtension = $matches[2]
            $this.Suffix = ""
        }
        $this.AOR = $rawData.aor  # Primary identifier
        
        # Map additional fields from raw data
        $this.SubscriberName = $rawData.subscriber_name
        $this.SubscriberDomain = $rawData.subscriber_domain
        $this.AORUser = $rawData.aor_user
        $this.AuthenticationKey = $rawData.authentication_key
        $this.SubscriberFullName = $rawData.sub_fullname
        $this.SubscriberLogin = $rawData.sub_login
        $this.SubscriberScope = $rawData.sub_scope
        $this.ServiceCode = $rawData.srvcode
        $this.CallerID911 = $rawData.callid_emgr
        $this.CallProcessingRule = $rawData.call_processing_rule
        $this.Mode = $rawData.mode
        $this.UserAgent = $rawData.user_agent
        $this.Hostname = $rawData.hostname
        $this.AddressIdSource = $rawData.address_id_source
        $this.AddressPrettyPrint = $rawData.address_pretty_print
        $this.Contact = $rawData.contact

        # Parse datetime fields if they exist
        if ($rawData.registration_time) {
            $this.RegistrationTime = [datetime]::ParseExact($rawData.registration_time, "yyyy-MM-dd HH:mm:ss", $null)
        }
        if ($rawData.registration_expires_time) {
            $this.RegistrationExpiresTime = [datetime]::ParseExact($rawData.registration_expires_time, "yyyy-MM-dd HH:mm:ss", $null)
        }
    }

    [string] ToString() {
        return $this.AOR
    }
}

class NSSubscriber : NSBaseObject {
    [string]$Domain
    [string]$User
    [string]$FirstName
    [string]$LastName
    [string]$FullName
    [string]$Email
    [string]$CallerIdName
    [string]$CallerIdNumber
    [string]$Scope
    [bool]$VMailProvisioned
    [string]$Site
    [string]$Login
    [string]$PIN
    [string]$Timezone
    [string]$VMailGreeting
    [bool]$VMailEnabled
    [string]$DialPlan
    [string]$CallerID911
    [string]$AreaCode
    [string]$Presence
    [bool]$DirList
    [string]$ServiceCode
    [string]$AccountStatus
    [NSDevice[]]$Devices

    NSSubscriber([PSCustomObject]$rawData) : base($rawData) {
        $this.Domain = $rawData.domain
        $this.User = $rawData.user
        $this.FirstName = $rawData.first_name
        $this.LastName = $rawData.last_name
        $this.FullName = $($this.FirstName).Trim() + ' ' + $($this.LastName).Trim()
        $this.Email = $rawData.email
        $this.CallerIdName = $rawData.callid_name
        $this.CallerIdNumber = $rawData.callid_nmbr
        $this.Scope = $rawData.scope
        $this.VMailProvisioned = ($rawData.vmail_provisioned -eq 'yes') -and $true -or ($rawData.vmail_provisioned -and $false)
        $this.Site = $rawData.site
        $this.Login = $rawData.subscriber_login
        $this.PIN = $rawData.subscriber_pin
        $this.Timezone = $rawData.time_zone
        $this.VMailGreeting = $rawData.vmail_greeting
        $this.VMailEnabled = ($rawData.vmail_enabled -eq 'yes') -and $true -or ($rawData.vmail_enabled -and $false)
        $this.DialPlan = $rawData.dial_plan
        $this.CallerID911 = $rawData.callid_emgr
        $this.AreaCode = $rawData.area_code
        $this.Presence = $rawData.presence
        $this.DirList = ($rawData.dir_list -eq 'yes') -and $true -or ($rawData.dir_list -and $false)
        $this.ServiceCode = $rawData.srvcode
        $this.AccountStatus = $rawData.account_status
        $this.Devices = @()
    }
}

class NSAddress : NSBaseObject {
    [string]$AddressId
    [string]$Domain
    [string]$Name
    [string]$Description
    [string]$Type
    [string]$Status
    [string]$PrettyPrint
    [string]$Source
    [string]$IpAddress
    [bool]$IsEndpoint
    [int]$ErrorCode

    NSAddress([PSCustomObject]$rawData) : base($rawData) {
        $this.AddressId = $rawData.address_id
        $this.Domain = $rawData.domain
        $this.Name = $rawData.address_name
        $this.Description = $rawData.description
        $this.Type = $rawData.type
        $this.Status = $rawData.status
        $this.PrettyPrint = $rawData.address_pretty_print
        $this.Source = $rawData.address_id_source
        $this.IpAddress = $rawData.address_ip
        $this.IsEndpoint = [bool]::TryParse($rawData.is_endpoint_callid, [ref]$null) ? [bool]::Parse($rawData.is_endpoint_callid) : $false
        $this.ErrorCode = [int]::TryParse($rawData.ndperror, [ref]$null) ? [int]::Parse($rawData.ndperror) : 0
    }

    [string] ToString() {
        return "$($this.Name) ($($this.AddressId))"
    }
}

class NSAddressEndpoint : NSBaseObject {
    [string]$address_id
    [string]$domain
    [string]$address_name
    [string]$caller_name
    [string]$address_line_1
    [string]$address_line_2
    [string]$city
    [string]$state_code
    [string]$zip
    [string]$country_code
    [string]$location
    [string]$public_ip
    [string]$standardized
    [string]$carrier

    NSAddressEndpoint([PSCustomObject]$rawData) : base($rawData) {
        $this.address_id = $rawData.address_id
        $this.domain = $rawData.domain
        $this.address_name = $rawData.address_name
        $this.caller_name = $rawData.caller_name
        $this.address_line_1 = $rawData.address_line_1
        $this.address_line_2 = $rawData.address_line_2
        $this.city = $rawData.city
        $this.state_code = $rawData.state_code
        $this.zip = $rawData.zip
        $this.country_code = $rawData.country_code
        $this.location = $rawData.location
        $this.public_ip = $rawData.public_ip
        $this.standardized = $rawData.standardized
        $this.carrier = $rawData.carrier
    }

    [string] ToString() {
        return "$($this.address_name) ($($this.address_id))"
    }
}

class NSAgentLog : NSBaseObject {
    [string]$AgentId
    [string]$Domain
    [string]$Action
    [string]$Status
    [datetime]$Timestamp
    [string]$Details

    NSAgentLog([PSCustomObject]$rawData) : base($rawData) {
        $this.AgentId = $rawData.agent_id
        $this.Domain = $rawData.domain
        $this.Action = $rawData.action
        $this.Status = $rawData.status
        $this.Timestamp = [datetime]::TryParse($rawData.timestamp, [ref]$null) ? [datetime]::Parse($rawData.timestamp) : [datetime]::MinValue
        $this.Details = $rawData.details
    }

    [string] ToString() {
        return "[$($this.Timestamp)] $($this.Action): $($this.Status)"
    }
}

class NSAnswerRule : NSBaseObject {
    [string]$RuleId
    [string]$Domain
    [string]$Name
    [string]$Description
    [string]$Type
    [string]$Pattern
    [string]$Action
    [bool]$Enabled
    [int]$Priority
    [datetime]$LastModified

    NSAnswerRule([PSCustomObject]$rawData) : base($rawData) {
        $this.RuleId = $rawData.rule_id
        $this.Domain = $rawData.domain
        $this.Name = $rawData.name
        $this.Description = $rawData.description
        $this.Type = $rawData.type
        $this.Pattern = $rawData.pattern
        $this.Action = $rawData.action
        $this.Enabled = [bool]::TryParse($rawData.enabled, [ref]$null) ? [bool]::Parse($rawData.enabled) : $false
        $this.Priority = [int]::TryParse($rawData.priority, [ref]$null) ? [int]::Parse($rawData.priority) : 0
        $this.LastModified = [datetime]::TryParse($rawData.last_modified, [ref]$null) ? [datetime]::Parse($rawData.last_modified) : [datetime]::MinValue
    }

    [string] ToString() {
        return "$($this.Name) ($($this.RuleId))"
    }
}

class NSHuntGroup : NSBaseObject {
    [string]$Name
    [string]$Domain
    [string]$Type
    [string]$Status
    [string]$Description

    NSHuntGroup([PSCustomObject]$rawData) : base($rawData) {
        $this.Name = $rawData.huntgroup_name
        $this.Domain = $rawData.domain
        $this.Type = $rawData.type
        $this.Status = $rawData.status
        $this.Description = $rawData.description
    }

    [string] ToString() {
        return $this.Name
    }
}

class NSCallQueue : NSBaseObject {
    [string]$queue_name
    [string]$domain
    [string]$description
    [string]$default_user
    [string]$queue_option
    [string]$max_time
    [string]$wait_limit
    [string]$length_limit
    [string]$agent_required
    [string]$callback_max_hours
    [string]$queuedcall_count
    [string]$agent_count
    [string]$huntgroup_option
    [string]$connect_to
    [string]$run_stats
    [string]$sring_1st
    [string]$sring_inc
    [string]$auto_logout

    NSCallQueue([PSCustomObject]$rawData) : base($rawData) {
        $this.queue_name = $rawData.queue_name
        $this.domain = $rawData.domain
        $this.description = $rawData.description
        $this.default_user = $rawData.default_user
        $this.queue_option = $rawData.queue_option
        $this.max_time = $rawData.max_time
        $this.wait_limit = $rawData.wait_limit
        $this.length_limit = $rawData.length_limit
        $this.agent_required = $rawData.agent_required
        $this.callback_max_hours = $rawData.callback_max_hours
        $this.queuedcall_count = $rawData.queuedcall_count
        $this.agent_count = $rawData.agent_count
        $this.huntgroup_option = $rawData.huntgroup_option
        $this.connect_to = $rawData.connect_to
        $this.run_stats = $rawData.run_stats
        $this.sring_1st = $rawData.sring_1st
        $this.sring_inc = $rawData.sring_inc
        $this.auto_logout = $rawData.auto_logout
    }

    [string] ToString() {
        return "$($this.queue_name) ($($this.description))"
    }
}

class NSQueueAgent : NSBaseObject {
    [string]$device_aor
    [string]$huntgroup_name
    [string]$huntgroup_domain
    [string]$entry_option
    [string]$wrap_up_sec
    [string]$auto_ans
    [string]$entry_order
    [string]$entry_priority
    [string]$call_limit
    [string]$confirm_required
    [string]$entry_device
    [string]$entry_status
    [string]$owner_user
    [string]$owner_domain
    [string]$session_count
    [string]$error_info
    [string]$last_update
    [string]$device
    [string]$stat
    [string]$sub_firstname
    [string]$sub_lastname
    [string]$sub_login
    [string]$sub_fullname

    NSQueueAgent([PSCustomObject]$rawData) : base($rawData) {
        $this.device_aor = $rawData.device_aor
        $this.huntgroup_name = $rawData.huntgroup_name
        $this.huntgroup_domain = $rawData.huntgroup_domain
        $this.entry_option = $rawData.entry_option
        $this.wrap_up_sec = $rawData.wrap_up_sec
        $this.auto_ans = $rawData.auto_ans
        $this.entry_order = $rawData.entry_order
        $this.entry_priority = $rawData.entry_priority
        $this.call_limit = $rawData.call_limit
        $this.confirm_required = $rawData.confirm_required
        $this.entry_device = $rawData.entry_device
        $this.entry_status = $rawData.entry_status
        $this.owner_user = $rawData.owner_user
        $this.owner_domain = $rawData.owner_domain
        $this.session_count = $rawData.session_count
        $this.error_info = $rawData.error_info
        $this.last_update = $rawData.last_update
        $this.device = $rawData.device
        $this.stat = $rawData.stat
        $this.sub_firstname = $rawData.sub_firstname
        $this.sub_lastname = $rawData.sub_lastname
        $this.sub_login = $rawData.sub_login
        $this.sub_fullname = $rawData.sub_fullname
    }

    [string] ToString() {
        return "$($this.sub_fullname) ($($this.device_aor))"
    }
}

#EndRegion

#Region Variables
$script:NSConnection = $null
#EndRegion

#Region Public Functions

function Connect-NSServer {
    <#
    .SYNOPSIS
        Connects to the NetSapiens API
    .DESCRIPTION
        Establishes a connection to the NetSapiens API using the provided credentials and connection details
    .PARAMETER BaseUrl
        The base URL of the NetSapiens API (e.g., https://api.ucaasnetwork.com)
    .PARAMETER ClientId
        The client ID for API authentication
    .PARAMETER ClientSecret
        The client secret for API authentication
    .PARAMETER Credential
        PSCredential object containing username and password
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseUrl,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientSecret,
        
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credential
    )

    $script:NSConnection = [NSConnection]::new($BaseUrl, $ClientId, $ClientSecret)
    $script:NSConnection.Connect($Credential)
}

function Get-NSSubscriber {
    <#
    .SYNOPSIS
        Gets subscriber information from NetSapiens
    .DESCRIPTION
        Retrieves subscriber details including devices from the NetSapiens API
    .PARAMETER Domain
        The domain to search in
    .PARAMETER User
        Optional user to filter by
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        
        [Parameter(Mandatory = $false)]
        [string]$User
    )

    $params = @{
        domain = $Domain
    }
    if ($User) {
        $params['user'] = $User
    }

    $response = $script:NSConnection.InvokeRequest('subscriber', 'read', $params)
    
    $subscribers = @()
    foreach ($sub in $response) {
        $subscriber = [NSSubscriber]::new($sub)

        # Get devices for this subscriber
        $devices = Get-NSDevice -Domain $Domain -User $sub.user
        $subscriber.Devices = $devices

        $subscribers += $subscriber
    }

    return $subscribers
}

function Get-NSDevice {
    <#
    .SYNOPSIS
        Retrieves device details from NetSapiens
    .DESCRIPTION
        Retrieves device details for a specific domain and optionally a specific user.
        Each device is uniquely identified by its AOR (Address of Record/SIP address).
    .PARAMETER Domain
        The domain to search in
    .PARAMETER User
        Optional user to filter devices by
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        
        [Parameter(Mandatory = $false)]
        [string]$User
    )

    $params = @{
        object = "device"
        action = "read"
        domain = $Domain
        format = "json"
    }
    if ($User) {
        $params['user'] = $User
    }

    $response = $script:NSConnection.InvokeRequest('device', 'read', $params)
    
    $devices = @()
    foreach ($dev in $response) {
        $device = [NSDevice]::new($dev)
        $devices += $device
    }

    return $devices
}

function New-NSDevice {
    <#
    .SYNOPSIS
        Creates a new device in NetSapiens if it doesn't already exist
    .DESCRIPTION
        Creates a new device in NetSapiens with the specified parameters.
        The Device parameter (SIP address) serves as the unique identifier for the device.
        The Device parameter should be in the format "sip:####[a-z]@domain.com"
        where #### is the user's extension and [a-z] is an optional lowercase letter.
    .PARAMETER Domain
        The domain name for the device (e.g., "domain.service")
    .PARAMETER Device
        The full SIP address for the device (e.g., "sip:1234a@domain.service").
        This serves as the unique identifier for the device.
    .PARAMETER User
        The user extension (3-4 digits)
    .PARAMETER Mac
        The MAC address of the device (can be empty)
    .PARAMETER Model
        The model of the device (can be empty)
    .PARAMETER Type
        Optional device type (e.g., "SIP")
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $true)]
        [string]$Device,
        [Parameter(Mandatory = $true)]
        [string]$User,
        [Parameter(Mandatory = $false)]
        [string]$Mac = "",
        [Parameter(Mandatory = $false)]
        [string]$Model = "",
        [Parameter(Mandatory = $false)]
        [string]$Type = ""
    )

    begin {
        $validationErrors = @()
    }
    
    process {
        try {
            # Input validation
            if ($Domain.Length -lt 4) {
                Add-ValidationError "Domain name must be at least 4 characters long."
            }
            
            if (-not ($User -match '^\d{3,4}$')) {
                Add-ValidationError "User must be a 3 or 4 digit number."
            }

            # Validate Device SIP address format
            if (-not ($Device -match '(sip:)(\d+)([a-z]{0,2})?@([\w\.\-]+)')) {
                Add-ValidationError "Invalid Device SIP address format. Must be like 'sip:1234a@domain.com'"
            }
            else {
                if ($matches[1] -ne "sip:") {
                    Add-ValidationError "Device SIP address must start with 'sip:'"
                }
                if (-not ($matches[2] -match '^\d{3,4}$')) {
                    Add-ValidationError "Device SIP username must be 3 or 4 digits"
                }
                if ($matches[3] -and -not ($matches[3] -match '^[a-z]{0,2}$')) {
                    Add-ValidationError "Device SIP designator must be empty or a single lowercase letter"
                }
            }
            
            if ($Mac -and -not ($Mac -match '^([0-9A-Fa-f]{12})$')) {
                Add-ValidationError "Invalid MAC address format. Use format: 001122334455"
            }
            
            # Check for validation errors
            if ($validationErrors.Count -gt 0) {
                throw "Validation failed:`n$($validationErrors -join "`n")"
            }
            
            Write-Verbose "Checking for existing device with SIP address: $Device"
            $existingDevices = Get-NSDevice -Domain $Domain
            $existingDevice = $existingDevices | Where-Object { $_.AOR -eq $Device }
            
            if ($existingDevice) {
                Write-Verbose "Device with SIP address $Device already exists. Returning existing device."
                return $existingDevice
            }
            
            Write-Verbose "Creating new device..."
            $params = @{
                domain = $Domain
                device = $Device
                user   = $User
                mac    = $Mac
                model  = $Model
            }

            if ($Type) {
                $params['type'] = $Type
            }
            
            $response = $script:NSConnection.InvokeRequest('device', 'create', $params)
            
            # Give the API a moment to process
            Start-Sleep -Milliseconds 500
            
            # Verify the device was created
            $newDevice = Get-NSDevice -Domain $Domain | Where-Object { $_.AOR -eq $Device }
            
            if (-not $newDevice) {
                throw "Device creation failed. Device not found after creation."
            }
            
            return $newDevice
        }
        catch {
            $errorMessage = "Failed to create device: $($_.Exception.Message)"
            Write-Error $errorMessage
            throw $errorMessage
        }
    }
}

function Get-NSAddress {
    <#
    .SYNOPSIS
        Retrieves address information from NetSapiens
    .DESCRIPTION
        Gets address details for a specific domain and optionally filters by address ID or name
    .PARAMETER Domain
        The domain to search in
    .PARAMETER AddressId
        Optional address ID to filter by
    .PARAMETER Name
        Optional address name to filter by
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        
        [Parameter(Mandatory = $false)]
        [string]$AddressId,
        
        [Parameter(Mandatory = $false)]
        [string]$Name
    )

    $params = @{
        object = "address"
        action = "read"
        domain = $Domain
        format = "json"
    }

    if ($AddressId) {
        $params['address_id'] = $AddressId
    }
    if ($Name) {
        $params['address_name'] = $Name
    }

    $response = $script:NSConnection.InvokeRequest('address', 'read', $params)
    
    $addresses = @()
    foreach ($addr in $response) {
        $address = [NSAddress]::new($addr)
        $addresses += $address
    }

    return $addresses
}

function Get-NSAddressCount {
    <#
    .SYNOPSIS
        Gets the count of addresses in a domain
    .DESCRIPTION
        Returns the total number of addresses in the specified domain
    .PARAMETER Domain
        The domain to count addresses in
    .PARAMETER AddressId
        Optional address ID to filter by
    .PARAMETER Name
        Optional address name to filter by
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        
        [Parameter(Mandatory = $false)]
        [string]$AddressId,
        
        [Parameter(Mandatory = $false)]
        [string]$Name
    )

    $params = @{
        object = "address"
        action = "count"
        domain = $Domain
        format = "json"
    }

    if ($AddressId) {
        $params['address_id'] = $AddressId
    }
    if ($Name) {
        $params['address_name'] = $Name
    }

    $response = $script:NSConnection.InvokeRequest('address', 'count', $params)
    return [int]$response.total
}

function New-NSAddress {
    <#
    .SYNOPSIS
        Creates a new address in NetSapiens
    .DESCRIPTION
        Creates a new address with the specified parameters
    .PARAMETER Domain
        The domain for the address
    .PARAMETER Name
        The name of the address
    .PARAMETER Type
        The type of address
    .PARAMETER Description
        Optional description for the address
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [string]$Type,
        
        [Parameter(Mandatory = $false)]
        [string]$Description = ""
    )

    $params = @{
        object       = "address"
        action       = "create"
        domain       = $Domain
        address_name = $Name
        type         = $Type
        format       = "json"
    }

    if ($Description) {
        $params['description'] = $Description
    }

    $response = $script:NSConnection.InvokeRequest('address', 'create', $params)
    return Get-NSAddress -Domain $Domain -AddressId $response.address_id
}

function Remove-NSAddress {
    <#
    .SYNOPSIS
        Deletes an address from NetSapiens
    .DESCRIPTION
        Removes the specified address from the system
    .PARAMETER Domain
        The domain of the address
    .PARAMETER AddressId
        The ID of the address to delete
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        
        [Parameter(Mandatory = $true)]
        [string]$AddressId
    )

    $params = @{
        object     = "address"
        action     = "delete"
        domain     = $Domain
        address_id = $AddressId
        format     = "json"
    }

    $script:NSConnection.InvokeRequest('address', 'delete', $params)
}

function Copy-NSAddressEndpoint {
    <#
    .SYNOPSIS
        Copies an endpoint address to another domain
    .DESCRIPTION
        Creates a copy of an endpoint address in a different domain
    .PARAMETER OriginalDomain
        The source domain
    .PARAMETER TargetDomain
        The target domain
    .PARAMETER AddressId
        The ID of the address to copy
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OriginalDomain,
        
        [Parameter(Mandatory = $true)]
        [string]$TargetDomain,
        
        [Parameter(Mandatory = $true)]
        [string]$AddressId
    )

    $params = @{
        object              = "address"
        action              = "copyEndpoint"
        original_domain     = $OriginalDomain
        to_domain           = $TargetDomain
        original_address_id = $AddressId
        format              = "json"
    }

    $response = $script:NSConnection.InvokeRequest('address', 'copyEndpoint', $params)
    return Get-NSAddress -Domain $TargetDomain -AddressId $response.address_id
}

function Get-NSAddressEndpoint {
    <#
    .SYNOPSIS
        Gets address endpoints from NetSapiens
    .DESCRIPTION
        Returns a list of address endpoints in the specified domain
    .PARAMETER Domain
        The domain to get address endpoints from
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    $params = @{
        domain  = $Domain
        carrier = 'bandwidth'  # Always set to 'bandwidth' as required
    }

    Write-Verbose "Getting address endpoints for domain: $Domain"
    $response = $script:NSConnection.InvokeRequest('address', 'readAddressEndpoint', $params)
    Write-Verbose "Address endpoint response: $($response | ConvertTo-Json -Depth 10)"
    
    if ($null -eq $response) {
        Write-Verbose "No address endpoints found"
        return @()
    }

    if ($response -is [System.Collections.IEnumerable] -and $response -isnot [string]) {
        Write-Verbose "Converting multiple address endpoints"
        return $response | ForEach-Object { [NSAddressEndpoint]::new($_) }
    }
    else {
        Write-Verbose "Converting single address endpoint"
        return @([NSAddressEndpoint]::new($response))
    }
}

function Update-NSAddress {
    <#
    .SYNOPSIS
        Updates an existing address
    .DESCRIPTION
        Modifies the properties of an existing address
    .PARAMETER Domain
        The domain of the address
    .PARAMETER AddressId
        The ID of the address to update
    .PARAMETER Name
        Optional new name for the address
    .PARAMETER Type
        Optional new type for the address
    .PARAMETER Description
        Optional new description for the address
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        
        [Parameter(Mandatory = $true)]
        [string]$AddressId,
        
        [Parameter(Mandatory = $false)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Type,
        
        [Parameter(Mandatory = $false)]
        [string]$Description
    )

    $params = @{
        object     = "address"
        action     = "update"
        domain     = $Domain
        address_id = $AddressId
        format     = "json"
    }

    if ($Name) {
        $params['address_name'] = $Name
    }
    if ($Type) {
        $params['type'] = $Type
    }
    if ($Description) {
        $params['description'] = $Description
    }

    $response = $script:NSConnection.InvokeRequest('address', 'update', $params)
    return Get-NSAddress -Domain $Domain -AddressId $AddressId
}

function Update-NSAddressEndpoint {
    <#
    .SYNOPSIS
        Updates an endpoint address
    .DESCRIPTION
        Modifies the properties of an endpoint address
    .PARAMETER Domain
        The domain of the address
    .PARAMETER AddressId
        The ID of the address to update
    .PARAMETER User
        The user associated with the endpoint
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        
        [Parameter(Mandatory = $true)]
        [string]$AddressId,
        
        [Parameter(Mandatory = $true)]
        [string]$User
    )

    $params = @{
        object     = "address"
        action     = "updateUserEndpoint"
        domain     = $Domain
        address_id = $AddressId
        user       = $User
        format     = "json"
    }

    $response = $script:NSConnection.InvokeRequest('address', 'updateUserEndpoint', $params)
    return Get-NSAddress -Domain $Domain -AddressId $AddressId
}

function Get-NSHuntGroup {
    <#
    .SYNOPSIS
        Retrieves hunt group information from NetSapiens
    .DESCRIPTION
        Gets hunt group details for a specific domain and optionally filters by hunt group name
    .PARAMETER Domain
        The domain to search in
    .PARAMETER HuntGroupName
        Optional hunt group name to filter by
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        
        [Parameter(Mandatory = $false)]
        [string]$HuntGroupName
    )

    $params = @{
        object = "huntgroup"
        action = "read"
        domain = $Domain
        format = "json"
    }

    if ($HuntGroupName) {
        $params['huntgroup_name'] = $HuntGroupName
    }

    $response = $script:NSConnection.InvokeRequest('huntgroup', 'read', $params)
    
    $huntGroups = @()
    foreach ($hg in $response) {
        $huntGroup = [NSHuntGroup]::new($hg)
        $huntGroups += $huntGroup
    }

    return $huntGroups
}

function Get-NSCallQueue {
    <#
    .SYNOPSIS
        Gets call queues from NetSapiens
    .DESCRIPTION
        Returns a list of call queues in the specified domain
    .PARAMETER Domain
        The domain to get call queues from
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    $params = @{
        domain = $Domain
    }

    Write-Verbose "Getting call queues for domain: $Domain"
    $response = $script:NSConnection.InvokeRequest('callqueue', 'read', $params)
    Write-Verbose "Call queue response: $($response | ConvertTo-Json -Depth 10)"
    
    if ($null -eq $response) {
        Write-Verbose "No call queues found"
        return @()
    }

    if ($response -is [System.Collections.IEnumerable] -and $response -isnot [string]) {
        Write-Verbose "Converting multiple call queues"
        return $response | ForEach-Object { [NSCallQueue]::new($_) }
    }
    else {
        Write-Verbose "Converting single call queue"
        return @([NSCallQueue]::new($response))
    }
}

function Get-NSQueueAgents {
    <#
    .SYNOPSIS
        Gets agents in a call queue from NetSapiens
    .DESCRIPTION
        Returns a list of agents in the specified call queue
    .PARAMETER Domain
        The domain containing the agents to read
    .PARAMETER QueueName
        The name of the call queue containing the agents to read
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [string]$QueueName
    )

    $params = @{
        domain     = $Domain
        queue_name = $QueueName
    }

    Write-Verbose "Getting agents for queue '$QueueName' in domain: $Domain"
    $response = $script:NSConnection.InvokeRequest('agent', 'read', $params)
    Write-Verbose "Agent response: $($response | ConvertTo-Json -Depth 10)"
    
    if ($null -eq $response) {
        Write-Verbose "No agents found"
        return @()
    }

    if ($response -is [System.Collections.IEnumerable] -and $response -isnot [string]) {
        Write-Verbose "Converting multiple agents"
        return $response | ForEach-Object { [NSQueueAgent]::new($_) }
    }
    else {
        Write-Verbose "Converting single agent"
        return @([NSQueueAgent]::new($response))
    }
}

function Get-NSDeviceCount {
    <#
    .SYNOPSIS
        Gets the count of devices in a domain
    .DESCRIPTION
        Returns the total number of devices in the specified domain, optionally filtered by territory, user, AOR, or device name
    .PARAMETER Domain
        The domain to count devices in
    .PARAMETER Territory
        Optional territory to filter by
    .PARAMETER User
        Optional user to filter by. Can be a string or an NSSubscriber object
    .PARAMETER AOR
        Optional Address of Record to filter by. Can be a string or an NSDevice object
    .PARAMETER Device
        Optional device name to filter by. Can be a string or an NSDevice object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $false)]
        [string]$Territory,

        [Parameter(Mandatory = $false)]
        [object]$User,

        [Parameter(Mandatory = $false)]
        [object]$AOR,

        [Parameter(Mandatory = $false)]
        [object]$Device
    )

    # Validate that only one optional parameter is provided
    $optionalParams = @{
        'Territory' = $Territory
        'User' = $User
        'AOR' = $AOR
        'Device' = $Device
    }
    $providedParams = $optionalParams.GetEnumerator() | Where-Object { 
        $null -ne $_.Value -and $_.Value -ne '' 
    }
    if ($providedParams.Count -gt 1) {
        $providedList = ($providedParams | ForEach-Object { $_.Key }) -join ', '
        throw "Only one optional parameter (Territory, User, AOR, or Device) can be specified at a time. Provided: $providedList"
    }

    $params = @{
        domain = $Domain
    }

    # Handle optional parameters
    if ($Territory) {
        $params['territory'] = $Territory
    }
    elseif ($User) {
        if ($User -is [NSSubscriber]) {
            $params['user'] = $User.User
        }
        else {
            $params['user'] = $User.ToString()
        }
    }
    elseif ($AOR) {
        if ($AOR -is [NSDevice]) {
            $params['aor'] = $AOR.AOR
        }
        else {
            $params['aor'] = $AOR.ToString()
        }
    }
    elseif ($Device) {
        if ($Device -is [NSDevice]) {
            $params['device'] = $Device.AOR
        }
        else {
            $params['device'] = $Device.ToString()
        }
    }

    Write-Verbose "Getting device count with parameters: $($params | ConvertTo-Json)"
    $response = $script:NSConnection.InvokeRequest('device', 'count', $params)
    
    if ($null -eq $response -or -not $response.total) {
        Write-Verbose "No count returned, defaulting to 0"
        return 0
    }

    Write-Verbose "Device count: $($response.total)"
    return [int]$response.total
}

#EndRegion

#Region Private Functions
function private:Write-NSDebug {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    
    if ($VerbosePreference -eq 'Continue') {
        Write-Verbose -Message $Message
    }
}

function Add-ValidationError {
    param([string]$Message)
    $script:validationErrors += $Message
    Write-Verbose "Validation Error: $Message"
}
#EndRegion
