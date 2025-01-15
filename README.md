# NetSapiens PowerShell Module

A PowerShell module for interacting with the NetSapiens API, providing object-oriented access to common NetSapiens operations.

## Features

- Modern PowerShell 7+ compatible with cross-platform support
- Object-oriented design with proper class implementations
- Efficient caching of API responses
- Automatic token refresh handling
- Type-safe parameter validation
- Comprehensive error handling
- Verbose debugging support

## Requirements

- PowerShell 7.0 or later (some features may work with PowerShell 5.1)
- Network access to NetSapiens API endpoint
- Valid NetSapiens API credentials

## Installation

1. Clone this repository or download the module files
2. Copy the NetSapiens folder to your PowerShell modules directory
3. Import the module:

```powershell
Import-Module NetSapiens
```

## Quick Start

```powershell
# Connect to NetSapiens
$credential = Get-Credential
Connect-NetSapiens -BaseUrl "https://api.ucaasnetwork.com" -ClientId "your_client_id" -ClientSecret "your_client_secret" -Credential $credential

# Get subscribers for a domain
$subscribers = Get-NSSubscriber -Domain "your_domain"

# Get devices for a specific user
$devices = Get-NSDevice -Domain "your_domain" -User "username"

# Create a new device
$newDevice = New-NSDevice -Domain "your_domain" `
                         -User "username" `
                         -Type "SIP" `
                         -Mac "00:11:22:33:44:55" `
                         -Model "Generic" `
                         -Vendor "Generic" `
                         -Description "Test Device"
```

## Available Commands

- `Connect-NetSapiens` - Establishes a connection to the NetSapiens API
- `Get-NSSubscriber` - Retrieves subscriber information
- `Get-NSDevice` - Retrieves device information
- `New-NSDevice` - Creates a new device

## Debugging

To enable verbose debug output, set the VerbosePreference:

```powershell
$VerbosePreference = 'Continue'
```

## Testing

Use the included `Test-NetSapiens.ps1` script to test the module's functionality. Update the configuration variables with your API credentials before running.

## Security Notes

- API credentials are handled securely using PowerShell's SecureString
- Token refresh is handled automatically
- All sensitive data is cleared from memory when possible
- HTTPS is enforced for all API communications

## Contributing

Contributions are welcome! Please submit pull requests with any improvements.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
