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

function Get-SpfRecordIpNetwork
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [DnsApi.SpfRecord]$SpfRecord
    )

    process
    {
        Write-Verbose "Processing $spfRecord"
        $SpfRecord.Entries | Where-Object { $_ -is [System.Net.IPNetwork] }
    }
}

function Get-SpfRecordIpAddress
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [DnsApi.SpfRecord]$SpfRecord
    )

    process
    {
        Write-Verbose "Processing $spfRecord"
        $SpfRecord.Entries | Where-Object { $_ -is [System.Net.IPAddress] }
    }
}

Init