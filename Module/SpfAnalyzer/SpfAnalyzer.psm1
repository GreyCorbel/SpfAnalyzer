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

function Test-SpfRecord
{
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$RawRecord,
        [Parameter(Mandatory)]
        [string]$Domain
    )

    process
    {
        $spfRecord = [DnsApi.DOmain]::ParseSpfRecord($Domain, $RawRecord)
        $spfRecord
    }
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
        $SpfRecord.Entries | Where-Object { $_ -is [DnsApi.SpfIpNetwork] }
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
        $SpfRecord.Entries | Where-Object { $_ -is [DnsApi.SpfIpAddress] }
    }
}

Init