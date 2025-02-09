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
        [string]$Domain,
        [Parameter()]
        [string[]]$DnsServerIpAddress
    )

    begin
    {
        $logger = new-object AutomationHelper.Logger($PSCmdlet)
        $parsedRecord = $null
        $dns = new-object SpfAnalyzer.Dns($DnsServerIpAddress)
    }
    process
    {
        $dnsName = '_dmarc.{0}' -f $domain
        $records = $dns.GetDmarcRecord($dnsName)
        foreach($record in $records)
        {
            if([SpfAnalyzer.DmarcRecord]::TryParse($domain, $dnsName, $record, $logger, [ref] $parsedRecord))
            {
                $parsedRecord
            }
        }
    }    
}
