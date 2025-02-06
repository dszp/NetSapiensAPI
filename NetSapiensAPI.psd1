# Module manifest for module 'NetSapiensAPI'
@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'NetSapiensAPI.psm1'

    # Version number of this module.
    ModuleVersion = '0.1.1'

    # ID used to uniquely identify this module
    GUID = 'f8b0e1a0-5b0a-4b0a-9b0a-5b0a4b0a9b0a'

    # Author of this module
    Author = 'David Szpunar'

    # Company or vendor of this module
    CompanyName = ''

    # Copyright statement for this module
    Copyright = '(c) 2025 David Szpunar. All rights reserved. https://david.szpunar.com/'

    # Description of the functionality provided by this module
    Description = 'PowerShell module for interacting with NetSapiens API'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '7.0'

    # Functions to export from this module, for use by using module
    FunctionsToExport = @(
        # Connection Management
        'Connect-NSServer',
        
        # Device Management
        'Get-NSDevice',
        'New-NSDevice',
        'Get-NSDeviceCount',
        
        # Address Management
        'Get-NSAddress',
        'Get-NSAddressCount',
        'Get-NSAddressEndpoint',
        
        # Subscriber Management
        'Get-NSSubscriber',
        
        # Queue Management
        'Get-NSCallQueue',
        'Get-NSQueueAgents'
    )

    # Variables to export from this module
    VariablesToExport = '*'

    # Aliases to export from this module
    AliasesToExport = '*'

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @('NetSapiens', 'API', 'VoIP', 'Telephony')

            # A URL to the license for this module.
            LicenseUri = 'https://github.com/dszp/NetSapiensAPI/blob/main/LICENSE'

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/dszp/NetSapiensAPI'

            # ReleaseNotes of this module
            ReleaseNotes = 'Version 0.1.1 of this module contains a fix to properly return the Service Code of an extension for proper filtering of system devices.'
        }
    }
}
