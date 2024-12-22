function Init
{
    Add-Type -Path (Join-Path $PSScriptRoot 'lib' 'net8.0' 'DnsApiLib.dll')
}

function Get-SPFRecord
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Domain
    )

    [DnsApi.Domain]::GetSpfRecord($Domain)
}

Init