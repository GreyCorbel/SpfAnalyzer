function Get-DmarcRecord
{
<#
.SYNOPSIS
    Retrieves and parses Dmarc record for given domain

.DESCRIPTION
    This command takes given DNS domain and tries to load and interpret dmarc record, if the domain publishes one
.OUTPUTS
    DmarcRecord[]

.EXAMPLE
Get-DmarcRecord -Domain 'microsoft.com'

Description
-----------
Retrieves and parses Dmarc record for microsoft.com domain

.LINK
More about SPF, see http://www.openspf.org/ and https://tools.ietf.org/html/rfc7208
#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Domain
    )

    process
    {
        $dnsName = '_dmarc.{0}' -f $domain
        $records = [SpfAnalyzer.Dns]::GetDmarcRecord($dnsName)
        foreach($record in $records)
        {
            [SpfAnalyzer.DmarcRecord]::Parse($domain, $dnsName, $record)
        }
    }    
}
