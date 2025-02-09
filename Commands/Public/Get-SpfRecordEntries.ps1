function Get-SpfRecordEntries
{
<#
.SYNOPSIS
    Retrieves SPF record for domain, or takes parsed SPF record and parses it

.DESCRIPTION
    This command retrieves SPF record for domain, or takes raw SPF record and parses it. Returns only entries of type SpfEntry from parsed record.
    SpfEntry represents parsed token from SPF record, like ip4, ip6, mx, a, include, redirect, exp, etc. It also contains information about SPF record it was parsed from.
.OUTPUTS
    SpfEntry[]

.EXAMPLE
Get-SpfRecordEntries -Domain 'microsoft.com'

Description
-----------
Retrieves and parses SPF record for microsoft.com domain

.EXAMPLE
Test-SpfRecord -RawRecord 'v=spf1 include:spf.protection.outlook.com -all' -Domain 'mydomain.com' | Get-SpfRecordEntries

Description
-----------
Retrieves and parses raw SPF record for domain mydomain.com and returs parsed entries

.LINK
More about SPF, see http://www.openspf.org/ and https://tools.ietf.org/html/rfc7208
#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Record')]
        [SpfAnalyzer.SpfRecord]$SpfRecord,
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'DomainName')]
        [string]$Domain,
        [Parameter(ParameterSetName = 'DomainName')]
        [string[]]$DnsServerIpAddress

    )

    
    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'DomainName')
        {
            Write-Verbose "Processing $Domain"
            $record = Get-SpfRecord -Domain $Domain -DnsServerIpAddress $DnsServerIpAddress
        }
        else
        {
            $record = $SpfRecord
        }
        Write-Verbose "Processing $record"
        $record.Entries
    }    
}
