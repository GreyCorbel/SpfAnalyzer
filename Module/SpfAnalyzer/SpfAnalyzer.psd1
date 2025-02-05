#
# Module manifest for module 'SpfAnalyzer'
#
# Generated by: JiriFormacek
#
# Generated on: 12/22/2024
#

@{

# Script module or binary module file associated with this manifest.
RootModule = '.\SpfAnalyzer.psm1'

# Version number of this module.
ModuleVersion = '2.0.0'

# Supported PSEditions
CompatiblePSEditions = @('Core')

# ID used to uniquely identify this module
GUID = 'abf30399-2e6d-4cd5-8624-f63b79c9bc9a'

# Author of this module
Author = 'Jiri Formacek'

# Company or vendor of this module
CompanyName = 'GreyCorber Solution'

# Copyright statement for this module
Copyright = '(c) Jiri Formacek. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Module provides functions for SPF record analysis.'

# Minimum version of the PowerShell engine required by this module
PowerShellVersion = '7.2'

# Name of the PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# ClrVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @('')

# Assemblies that must be loaded prior to importing this module
RequiredAssemblies = @('.\lib\net8.0\SpfAnalyzer.dll',  '.\lib\net8.0\AutomationHelper.dll', '.\lib\net8.0\SpfIpHelper.dll', '.\lib\net8.0\DnsClient.dll')

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
FormatsToProcess = @( '.\SpfAnalyzer.format.ps1xml' )

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @('Get-SpfRecord', 'Test-SpfRecord', 'Test-SpfHost', 'Get-SpfRecordIpAddress', 'Get-SpfRecordIpNetwork','Get-SpfRecordEntries', 'Get-DKIMRecord', 'Get-DmarcRecord')

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @()

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @()

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
FileList = @( './SpfAnalyzer.psd1', './SpfAnalyzer.psm1', './SpfAnalyzer.format.ps1xml',
            './lib/net8.0/SpfIpHelper.dll', './lib/net8.0/DnsClient.dll','./lib/net8.0/SpfAnalyzer.dll', './lib/net8.0/AutomationHelper.dll' )

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @('Spf', 'Analyzer', 'Dns', 'DMarc', 'EmailSecurity')

        # A URL to the license for this module.
        LicenseUri = 'https://raw.githubusercontent.com/GreyCorbel/SpfAnalyzer/master/LICENSE'

        # A URL to the main website for this project.
         ProjectUri = 'https://github.com/GreyCorbel/SpfAnalyzer'
        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        # ReleaseNotes = ''

        # Prerelease string of this module
        Prerelease = 'beta6'

        # Flag to indicate whether the module requires explicit user acceptance for install/update/save
        # RequireLicenseAcceptance = $false

        # External dependent modules of this module
        # ExternalModuleDependencies = @('')

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

