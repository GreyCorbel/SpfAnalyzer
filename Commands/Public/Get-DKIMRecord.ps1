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
Get-DkimRecord -Domain 'microsoft.com'

Description
-----------
Retrieves and parses DKIM record for microsoft.com domain

.LINK
More about SPF, see http://www.openspf.org/ and https://tools.ietf.org/html/rfc7208
#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Domain,
        [string]$Record
    )

    process
    {
        $dnsName = $record + '.' + $domain
        $dkimRecords = [Dns]::GetDkimRecord($dnsName)
        foreach($record in $dkimRecords)
        {
            [DkimRecord]::Parse($domain, $dnsName, $record)
        }
    }    
}
