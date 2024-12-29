function Get-SpfRecordIpNetwork
{
<#
.SYNOPSIS
    Retrieves SPF record for domain, or takes parsed SPF record and returns only IP networks from it

.DESCRIPTION
    This command retrieves SPF record for domain, or takes raw SPF record and parses it. Returns IPv6 or IPv6 networks from parsed record.
    SpfIpNetwork represents parsed IP network from SPF record from ip4, ip6, include and redirect record entries. It also contains information about SPF record it was parsed from.
.OUTPUTS
    SpfIpNetwork[]

.EXAMPLE
Get-SpfRecord -Domain 'microsoft.com' | Get-SpfRecordIpNetwork

Description
-----------
Retrieves IP networks authorized for use with microsoft.com domain

.LINK
More about SPF, see http://www.openspf.org/ and https://tools.ietf.org/html/rfc7208
#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Record')]
        [SpfRecord]$SpfRecord,
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'DomainName')]
        [string]$Domain
    )

    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'DomainName')
        {
            Write-Verbose "Processing $Domain"
            [SpfRecord[]]$record = Get-SpfRecord -Domain $Domain 
        }
        else
        {
            $record = $SpfRecord
        }

        Write-Verbose "Processing $record"
        $record.Entries | Where-Object { $_ -is [SpfIpNetwork] }
    }
}
