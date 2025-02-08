#region Public commands
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
function Get-SpfRecordEntries
{
<#
.SYNOPSIS
    Retrieves SPF record for domain, or takes parsed SPF record and parses it

.DESCRIPTION
    This command retrieves SPF record for domain, or takes raw SPF record and parses it. Returns only entries of type SpfEntry from parsed record.
    SpfEntry represents parsed token from SPF record, like ip4, ip6, mx, a, include, redirect, exp, etc. It also contains information about SPF record it was parsed from.
.OUTPUTS
    SpfEntry[]

.EXAMPLE
Get-SpfRecordEntries -Domain 'microsoft.com'

Description
-----------
Retrieves and parses SPF record for microsoft.com domain

.EXAMPLE
Test-SpfRecord -RawRecord 'v=spf1 include:spf.protection.outlook.com -all' -Domain 'mydomain.com' | Get-SpfRecordEntries

Description
-----------
Retrieves and parses raw SPF record for domain mydomain.com and returs parsed entries

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
        [string]$DnsServerIpAddress

    )

    
    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'DomainName')
        {
            Write-Verbose "Processing $Domain"
            $record = Get-SpfRecord -Domain $Domain -DnsServerIpAddress $DnsServerIpAddress
        }
        else
        {
            $record = $SpfRecord
        }
        Write-Verbose "Processing $record"
        $record.Entries
    }    
}
function Get-SpfRecordIpAddress
{
<#
.SYNOPSIS
    Retrieves SPF record for domain, or takes parsed SPF record and returns only IP addresses from it

.DESCRIPTION
    This command retrieves SPF record for domain, or takes raw SPF record and parses it. Returns IPv6 or IPv6 addresses from parsed record.
    SpfIpAddress represents parsed IP address from SPF record from ip4, ip6, mx, a, include and redirect record entries. It also contains information about SPF record it was parsed from.
.OUTPUTS
    SpfIpAddress[]

.EXAMPLE
Get-SpfRecord -Domain 'microsoft.com' | Get-SpfRecordIpAddress

Description
-----------
Retrieves IP addresses authorized for use with microsoft.com domain

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
        [string]$DnsServerIpAddress
    )

    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'DomainName')
        {
            Write-Verbose "Processing $Domain"
            $record = Get-SpfRecord -Domain $Domain  -DnsServerIpAddress $DnsServerIpAddress
        }
        else
        {
            $record = $SpfRecord
        }

        Write-Verbose "Processing $record"
        $record.IpAddresses
    }
}
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
        [SpfAnalyzer.SpfRecord]$SpfRecord,
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'DomainName')]
        [string]$Domain,
        [Parameter(ParameterSetName = 'DomainName')]
        [string]$DnsServerIpAddress
    )

    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'DomainName')
        {
            Write-Verbose "Processing $Domain"
            $record = Get-SpfRecord -Domain $Domain -DnsServerIpAddress $DnsServerIpAddress
        }
        else
        {
            $record = $SpfRecord
        }

        Write-Verbose "Processing $record"
        $record.IpNetworks
    }
}
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
        [string]$DnsServerIpAddress,
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
function Test-SpfRecord
{
<#
.SYNOPSIS
    Parses raw SPF record
.DESCRIPTION
    This command parses raw SPF record and returns parsed SPF record object. This is useful when constructing SPF record from scratch to test it.
.OUTPUTS
    SpfRecord[]

.EXAMPLE
Test-SpfRecord -Domain 'mydomain.com' -RawRecord 'v=spf1 include:spf.protection.outlook.com -all'
Description
-----------
CHecks if SPF record can be parsed correctly.

.LINK
More about SPF, see http://www.openspf.org/ and https://tools.ietf.org/html/rfc7208
#>

param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$RawRecord,
        [Parameter(Mandatory)]
        [string]$Domain
    )

    begin
    {
        $logger = new-object AutomationHelper.Logger($PSCmdlet)
        $dns = new-object SpfAnalyzer.Dns
    }
    process
    {
        $parsedRecord = $null
        if([SpfAnalyzer.SpfRecord]::TryParse($dns, $Domain, $Domain, $RawRecord, 0, $logger, [ref] $parsedRecord))
        {
            $parsedRecord
        }
    }
}
#endregion Public commands
#region Internal commands
function Expand-SpfMacro
{
    param (
        [Parameter(Mandatory = $true)]
        [string]$Macro,
        [Parameter(Mandatory)]
        [string]$Domain,
        [Parameter(Mandatory)]
        [System.Net.IPAddress]$IpAddress,
        [Parameter()]
        [string]$SenderAddress
    )

    process
    {
        $senderValid = [string]::IsNullOrEmpty($SenderAddress) -eq $false
        if($senderValid) {
            $senderParts = $SenderAddress.Split('@')
            $senderValid = $senderParts.Count -eq 2
        }
        if($macro -match '%{i}') {
            $dottedIp = [SpfIpHelper.IPAddressExtensions]::ToDotted($IpAddress)
            $macro = $macro -replace '%{i}', $dottedIp
        }
        if($macro -match '%{ir}') {
            $dottedIp = [SpfIpHelper.IPAddressExtensions]::ToReverseDotted($IpAddress)
            $macro = $macro -replace '%{ir}', $dottedIp
        }
        if($macro -match '%{c}') {
            $macro = $macro -replace '%{c}', $IpAddress.ToString()
        }
        if($macro -match '%{d}') {
            $macro = $macro -replace '%{d}', $Domain
        }
        if($macro -match '%{h}') {
            #we assume here that domain is a HELO domain
            $macro = $macro -replace '%{h}', $Domain
        }
        if($macro -match '%{s}' -and $senderValid) {
            $macro = $macro -replace '%{s}', $SenderAddress
        }
        if($macro -match '%{l}' -and $senderValid) {
            $macro = $macro -replace '%{l}', $senderParts[0]
        }
        if($macro -match '%{o}' -and $senderValid) {
            $macro = $macro -replace '%{o}', $senderParts[1]
        }
        if($macro -match '%{v}') {
            if($IpAddress.AddressFamily -eq 'InterNetwork') {
                $macro = $macro -replace '%{v}', 'in-addr'
            }
            else {
                $macro = $macro -replace '%{v}', 'ipv6'
            }
        }
        return $macro
    }
}
#endregion Internal commands
