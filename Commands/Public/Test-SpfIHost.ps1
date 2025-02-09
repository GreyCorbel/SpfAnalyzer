function Test-SpfHost
{
<#
.SYNOPSIS
    Tests IP address and sender against policy defined by SPF record
.DESCRIPTION
    This command tests IP address and optional sender to test them with SPF policy defined for domain or defined by SPF record. Command returns entries from SPF record that authorize or deny given IP address and sender.
    Sender information is only used if SPF record contains macros in exists entry that require it.
    Command basically provides the same functionality as SPF test tools like https://www.kitterman.com/spf/validate.html
.OUTPUTS
    SpfIpAddress[]
    SpfIpNetwork[]
    SpfEntry[]

.EXAMPLE
Get-SpfRecord -Domain 'microsoft.com' | Test-SpfHost -IpAddress '20.88.157.184'

Description
-----------
CHecks if IP address 20.88.157.184 is authorized to send email on behalf of microsoft.com

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
        [string[]]$DnsServerIpAddress,
        [Parameter(Mandatory)]
        [string]$IpAddress,
        [Parameter()]
        [string]$SenderAddress
    )

    process
    {
        $ip = [System.Net.IPAddress]::Parse($IpAddress)
        if ($PSCmdlet.ParameterSetName -eq 'DomainName')
        {
            Write-Verbose "Processing $Domain"
            $spfRecords = Get-SpfRecord -Domain $Domain -DnsServerIpAddress $DnsServerIpAddress
        }
        else
        {
            $spfRecords = @($SpfRecord)
        }
        Write-Verbose "Processing $record"
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
                $macro =  Expand-SpfMacro -Macro $_.Value -Domain $spfRecords[0].Source -IpAddress $ip -SenderAddress $SenderAddress
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
            $record.Entries `
            | Where-Object { $_.Prefix -eq 'include' } `
            | Where-Object { $_.Value -match '%{.' } `
            | ForEach-Object {
                $macro =  Expand-SpfMacro -Macro $_.Value -Domain $spfRecords[0].Source -IpAddress $ip -SenderAddress $SenderAddress
                if($macro -match '%{.' ) {
                    throw "Unsupported macro $macro after expansion of $( $_.Value )"
                }
                try {
                    $rawRecord = [Dns]::GetRecord($macro, [DnsClient.QueryType]::TXT)
                    if($null -ne $rawRecord)
                    {
                        $additionalRecord = [SpfAnalyzer.SpfRecord]::Parse($_.Source, $rawRecord)
                        $additionalRecord `
                        | Test-SpfHost -IpAddress $IpAddress -SenderAddress $SenderAddress
                    }
                }
                catch {
                    #silently ignore not found expanded macro
                }
            }
        }
    }
}