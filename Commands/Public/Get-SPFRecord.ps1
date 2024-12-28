function Get-SPFRecord
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Domain
    )

    process
    {
        $spfRecords = [Dns]::GetSpfRecord($domain)
        foreach($spfRecord in $spfRecords)
        {
            [SpfRecord]::Parse($domain, $spfRecord)
        }
    }    
}
