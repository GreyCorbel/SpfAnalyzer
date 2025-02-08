function Get-DkimRecord
{
<#
.SYNOPSIS
    Retrieves and parses given DKIM record

.DESCRIPTION
    This command takes given DNS record and tries to interpret it as DKIM record.
.OUTPUTS
    DkimRecord[]

.EXAMPLE
Get-DkimRecord -Domain 'microsoft.com' -Record 'selector1._domainkey'

Description
-----------
Retrieves and parses DKIM record selector1._domainKey for microsoft.com domain

.LINK
More about SPF, see http://www.openspf.org/ and https://tools.ietf.org/html/rfc7208
#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Domain,
        [Parameter(Mandatory)]
        [string]$Record,
        [Parameter()]
        [string]$DnsServerIpAddress
    )
    begin
    {
        $logger = new-object AutomationHelper.Logger($PSCmdlet)
        $parsedRecord = $null
        $dns = new-object SpfAnalyzer.Dns($DnsServerIpAddress)
    }
    process
    {
        $dnsName = $record + '.' + $domain
        $dkimRecords = $dns.GetDkimRecord($dnsName)
        foreach($record in $dkimRecords)
        {
            #we can have cname pointing to nowhere, so we need to check if we have any record value
            if($record.Value.Count -gt 0 -and [SpfAnalyzer.DkimRecord]::TryParse($domain, $dnsName, $record.Source, $record.Value[0], $logger, [ref] $parsedRecord))
            {
                $parsedRecord
            }
        }
    }    
}
