function Get-SpfRecordIpAddress
{
<#
.SYNOPSIS
    Retrieves SPF record for domain, or takes parsed SPF record and returns only IP addresses from it

.DESCRIPTION
    This command retrieves SPF record for domain, or takes raw SPF record and parses it. Returns IPv6 or IPv6 addresses from parsed record.
    SpfIpAddress represents parsed IP address from SPF record from ip4, ip6, mx, a, include and redirect record entries. It also contains information about SPF record it was parsed from.
.OUTPUTS
    SpfIpAddress[]

.EXAMPLE
Get-SpfRecord -Domain 'microsoft.com' | Get-SpfRecordIpAddress

Description
-----------
Retrieves IP addresses authorized for use with microsoft.com domain

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
        [string]$DnsServerIpAddress
    )

    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'DomainName')
        {
            Write-Verbose "Processing $Domain"
            $record = Get-SpfRecord -Domain $Domain  -DnsServerIpAddress $DnsServerIpAddress
        }
        else
        {
            $record = $SpfRecord
        }

        Write-Verbose "Processing $record"
        $record.IpAddresses
    }
}
