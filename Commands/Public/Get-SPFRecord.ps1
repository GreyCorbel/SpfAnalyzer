function Get-SPFRecord
{
<#
.SYNOPSIS
    Retrieves and parses SPF record for domain

.DESCRIPTION
    This command takes TXT records from provided domain, selects record representing SPF and parses it.
    Multi-string TXT records are concatenated into single string before parsing.
    In case record contains include method, additional records are retrieved and parsed as well, so output of this command is array of parsed SPF records.
.OUTPUTS
    SpfRecord[]

.EXAMPLE
Get-SpfRecord -Domain 'microsoft.com'

Description
-----------
Retrieves and parses SPF record for microsoft.com domain

.LINK
More about SPF, see http://www.openspf.org/ and https://tools.ietf.org/html/rfc7208
#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Domain,
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
        $spfRecords = $dns.GetSpfRecord($domain)
        foreach($spfRecord in $spfRecords)
        {
            $success = [SpfAnalyzer.SpfRecord]::TryParse($dns, $domain, $domain, $spfRecord, 0, $logger, [ref] $parsedRecord)
            if($success)
            {
                $parsedRecord
            }
        }
    }    
}
