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
        [string]$Record
    )

    process
    {
        $dnsName = $record + '.' + $domain
        $dkimRecords = [SpfAnalyzer.Dns]::GetDkimRecord($dnsName)
        foreach($record in $dkimRecords)
        {
            [SpfAnalyzer.DkimRecord]::Parse($domain, $dnsName, $record)
        }
    }    
}
