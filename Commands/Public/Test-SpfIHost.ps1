function Test-SpfHost
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$Domain,
        [Parameter(Mandatory)]
        [string]$Address,
        [Parameter()]
        [string]$SenderAddress
    )

    process
    {
        $ip = [System.Net.IPAddress]::Parse($Address)
        $spfRecords = Get-SPFRecord -Domain $Domain
        foreach($record in $spfRecords)
        {
            $record `
            | Get-SpfRecordIpAddress `
            | Where-Object { $_.Address -eq $ip }

            $record `
            | Get-SpfRecordIpNetwork `
            | Where-Object { $_.Contains($ip) }

            $record.Entries `
            | Where-Object { $_.Prefix -eq 'exists' } `
            | ForEach-Object {
                $macro =  Expand-SpfMacro -Macro $_.Value -Domain $Domain -IpAddress $ip -SenderAddress $SenderAddress
                if($macro -match '%{.' ) {
                    throw "Unsupported macro $macro after expansion of $( $_.Value )"
                }
                try {
                    [Dns]::GetRecord($macro, [DnsClient.QueryType]::A)
                }
                catch {
                    #silently ignore not found expanded macro
                }
            }
        }
    }
}