# NetSapiensAPI PowerShell Module

A PowerShell module for interacting with the NetSapiens API to manage subscribers, devices, addresses, and call queues.

## Installation

Place the `NetSapiensAPI` module folder next to your script files if not installing through official PowerShell means. The module is required to be in the same directory as any scripts using it.

## Features

The module provides the following key functionalities:

- Subscriber Management
- Device Management
- Address Management
- Call Queue Management

## Authentication

The module uses OAuth2 authentication. You'll need:
- Base URL for your NetSapiens instance
- Client ID
- Client Secret
- Username/Password credentials

## Available Functions

### Tested and Reliable Functions

These functions are thoroughly tested and demonstrated in the example scripts:

- `Connect-NSServer` - Establishes connection to NetSapiens server
- `Get-NSSubscriber` - Retrieves subscriber information
- `Get-NSDevice` - Gets device details
- `New-NSDevice` - Creates a new device
- `Get-NSDeviceCount` - Counts devices with optional filtering
- `Get-NSAddress` - Retrieves address information
- `Get-NSAddressCount` - Gets total address count
- `Get-NSAddressEndpoint` - Retrieves address endpoint details
- `Get-NSCallQueue` - Gets call queue information
- `Get-NSQueueAgents` - Retrieves agents in a call queue

### Additional Functions (Limited Testing)

These functions exist but may need additional testing:

- `Copy-NSAddressEndpoint` - Copies endpoint addresses between domains
- `Get-NSHuntGroup` - Retrieves hunt group information

## Field Reference

### Device Fields
- `AOR` - Address of Record (SIP address)
- `Domain` - Subscriber domain
- `User` - Subscriber name
- `Mac` - MAC address
- `Model` - Device model
- `Extension` - Base extension number
- `Suffix` - Optional extension suffix
- `FullExtension` - Complete extension (with suffix)
- `AuthenticationKey` - Device authentication key
- `Mode` - Device mode
- `UserAgent` - SIP user agent
- And more...

### Subscriber Fields
- `Domain` - Subscriber domain
- `User` - Username
- `FirstName` - First name
- `LastName` - Last name
- `FullName` - Complete name
- `Email` - Email address
- `CallerIdName` - Caller ID display name
- `CallerIdNumber` - Caller ID number

## Example Usage

Here are two example scripts showing how to use the module:

### Example 1: Testing Basic Functionality

```powershell
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$DomainName,

    [switch]$ShowQueueAgentDetails,
    [switch]$ShowDeviceDetails
)

# Import the module (must be in same directory as script)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptDir "NetSapiensAPI"
Import-Module $modulePath -Force

# Configure connection
$config = @{
    BaseUrl      = "https://api.example.com"
    ClientId     = "your_client_id"
    ClientSecret = "your_client_secret"
    Domain       = $DomainName
}

# Create credential object
$credential = Get-Credential

# Connect to NetSapiens
Connect-NSServer -BaseUrl $config.BaseUrl -ClientId $config.ClientId -ClientSecret $config.ClientSecret -Credential $credential

# Get and display subscribers
$subscribers = Get-NSSubscriber -Domain $DomainName
Write-Host "Found $($subscribers.Count) subscribers"

# Get devices for first subscriber
if ($subscribers.Count -gt 0) {
    $firstUser = $subscribers[0].User
    $devices = Get-NSDevice -Domain $config.Domain -User $firstUser
    
    # Display device information
    foreach ($device in $devices) {
        Write-Host "Device AOR: $($device.AOR)"
        Write-Host "Extension: $($device.Extension)"
        Write-Host "Auth Key: $($device.AuthenticationKey)"
    }
}

# Get and display addresses
$addresses = Get-NSAddress -Domain $config.Domain
Write-Host "Found $($addresses.Count) addresses"

# Get call queues and agents
if ($ShowQueueAgentDetails) {
    $callQueues = Get-NSCallQueue -Domain $DomainName
    foreach ($queue in $callQueues) {
        $agents = Get-NSQueueAgents -Domain $DomainName -QueueName $queue.queue_name
        Write-Host "Queue $($queue.queue_name) has $($agents.Count) agents"
    }
}
```

### Example 2: Creating a New Device

```powershell
[CmdletBinding()]
param (
    # The NetSapiens soft switch domain name (PBX domain--not necessarily a public DNS domain name)
    [Parameter(Mandatory = $true)]
    [string]$DomainName,

    # The number-only part of the extension
    [Parameter(Mandatory = $true)]
    [string]$Extension = "",

    # The optional extension suffix to add to the extension number when creating a new device.
    # Defaults to "r" making the extension created "1234r" for extension 1234.
    [Parameter(Mandatory = $false)]
    [string]$Suffix = "r",

    # Pass this switch to the script to use the caller ID name (if it exists) for an extension instead of the extension full name
    [Parameter(Mandatory = $false)]
    [switch]$UseCallerIdName,
    
    # Pass this switch to the script to allow creation of a new device on an extension with no existing devices.
    [Parameter(Mandatory = $false)]
    [switch]$CreateNewBillable
)

# Import module
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptDir "NetSapiensAPI"
Import-Module $modulePath -Force

# Configure and connect
$NsConfig = @{
    BaseUrl      = "https://api.example.com"
    ClientId     = "your_client_id"
    ClientSecret = "your_client_secret"
    Domain       = $DomainName
}

$credential = Get-Credential
Connect-NSServer -BaseUrl $NsConfig.BaseUrl -ClientId $NsConfig.ClientId -ClientSecret $NsConfig.ClientSecret -Credential $credential

# Get subscriber information
$subscriber = Get-NSSubscriber -Domain $DomainName -User $Extension

# Check existing devices
$extensionCount = Get-NSDeviceCount -Domain $DomainName -User $Extension
if ($extensionCount -eq 0 -and !$CreateNewBillable) {
    Write-Host "No devices found. Use -CreateNewBillable to create device on unbillable extension."
    exit 1
}

# Create new device
$newDevice = "sip:$Extension$Suffix@$DomainName"
$new_device = New-NSDevice -Domain $DomainName -Device $newDevice -User $Extension

# Display results
Write-Host "Created device: $($new_device.AOR)"
Write-Host "Authentication Key: $($new_device.AuthenticationKey)"
Write-Host "Extension: $($new_device.Extension)"
```

## Notes

- Always check device existence before creating new ones
- Use proper error handling in production code
- Keep authentication credentials secure
- The module caches some data for performance
- Functions return raw API data in the `RawData` property

For more information about the NetSapiens API, consult your NetSapiens documentation.

## Contributing

Contributions are welcome! Please submit pull requests with any improvements.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
