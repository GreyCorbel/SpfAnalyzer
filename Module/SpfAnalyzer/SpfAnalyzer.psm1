#region Enums
enum SpfAction {
    Pass
    Fail
    SoftFail
    Neutral
}
#endregion Enums
#region Classes
class Dns {
    hidden static [DnsClient.LookupClient]$client = [DnsClient.LookupClient]::new()

    static [object[]] GetRecord([string]$Name, [DnsClient.QueryType]$recordType) {
        $retVal = @()
        switch($recordType)
        {
            {$_ -in ([DnsClient.QueryType]::A, [DnsClient.QueryType]::AAAA)} { 
                $data = [Dns]::Client.Query($Name, $_) `
                | select-object -ExpandProperty Answers `
                | where-object{$_.RecordType -eq $recordType} `
                | select-object -ExpandProperty Address
                $data | foreach-object {
                    $retVal += [SpfIpAddress]::new($recordName, $_)
                }
                break;
            }
            {$_ -eq [DnsClient.QueryType]::MX} {
                $data = [Dns]::Client.Query($Name, $_) `
                | select-object -ExpandProperty Answers `
                | where-object{$_.RecordType -eq $recordType} `
                | select-object -expand Exchange `
                | select-object -expand Value
                $data | foreach-object {
                    $retVal += $_
                }
                break;
            }
            {$_ -eq [DnsClient.QueryType]::TXT} {
                [Dns]::Client.Query($Name, $_) `
                | select-object -ExpandProperty Answers `
                | where-object{$_.RecordType -eq $recordType} `
                | foreach-object {
                    #TXT records may be split into multiple strings
                    if($_.Text.Count -gt 1) {
                        $retVal += ($_.Text -join '')
                    }
                    else {
                        $retVal += $_.Text
                    }
                }
                break;
            }
            default {
                throw "Unsupported record type $recordType"
            }
        }
        if($retVal.Count -eq 0) {return $null} else {return $retVal}
    }

    static [object[]] GetSpfRecord([string]$Name) {
        $retVal = @()
        [Dns]::GetRecord($Name, [DnsClient.QueryType]::TXT) | foreach-object {
            if($_ -match "^v=spf1") {
                $retVal += $_
            }
        }
        if($retVal.Count -eq 0) {return $null} else {return $retVal}
    }
}
class SpfEntry {
    [string]$Source
    [string]$Prefix
    [string]$Value

    SpfEntry([string]$Source, [string]$prefix, [string]$value) {
        $this.Prefix = $prefix
        $this.Value = $value
        $this.Source = $Source
    }

    [string] ToString() {
        return "$($this.Prefix) $($this.Value)"
    }
}
class SpfIpAddress {
    [string]$Source
    [System.Net.IPAddress]$Address

    SpfIpAddress([string]$source, [System.Net.IPAddress]$address) {
        $this.Source = $source
        $this.Address = $address
    }

    [string] ToString() {
        return $this.Address.ToString()
    }

    [System.Net.IPNetwork] ToNetwork([int]$prefixLength) {
        return  [SpfIpNetwork]::new($this.source, [IpHelper.IPAddressExtensions]::Mask($this.address,$prefixLength,$true))
    }

    static [SpfIpAddress] Parse([string]$source, [string]$address) {
        try {
            $ip = [System.Net.IPAddress]::Parse($address)
            return [SpfIpAddress]::new($source, $ip)
        }
        catch {
            Write-Warning "Invalid IP address $address"
            return $null
        }            
    }
}
class SpfIpNetwork {
    hidden [System.Net.IPNetwork] $network

    [string]$Source
    [System.Net.IPAddress]$BaseAddress
    [int]$PrefixLength

    static [hashtable[]] $MemberDefinitions = @(
        @{
            MemberType  = 'ScriptProperty'
            MemberName  = 'BaseAddress'
            Value       = { $this.network.BaseAddress }
        }
        @{
            MemberType  = 'ScriptProperty'
            MemberName  = 'PrefixLength'
            Value       = { $this.network.PrefixLength }
        }
    )

    static SpfIpNetwork() {
        $TypeName = [SpfIpNetwork].Name
        foreach ($Definition in [SpfIpNetwork]::MemberDefinitions) {
            Update-TypeData -TypeName $TypeName -Force @Definition
        }
    }

    SpfIpNetwork() {}

    SpfIpNetwork([string]$source, [System.Net.IPNetwork]$network) {
        $this.Source = $source
        $this.network = $network
    }

    SpfIpNetwork([string]$source, [System.Net.IPAddress]$address, [int]$prefixLength) {
        $this.Source = $source
        #need compiled helper here to overcome powershell language limitations
        $this.network = [IpHelper.IPAddressExtensions]::Mask($address,$prefixLength,$true)
    }

    [bool] Contains([System.Net.IPAddress]$address) {
        return $this.network.Contains($address)
    }
    
    static [SpfIpNetwork] Parse([string]$source, [string]$address) {
        $parts = $address.Split('/')
        $ip = [System.Net.IPAddress]::Parse($parts[0])
        $mask = [int]$parts[1]
        return [SpfIpNetwork]::new($source, $ip, $mask)
    }

    [string] ToString() {
        return "$($this.BaseAddress)/$($this.PrefixLength)"
    }

}
class SpfRecord
{
    hidden [string] $rawRecord

    [string] $Version
    [SpfAction] $FinalAction
    [string] $Source
    [object[]] $Entries

    SpfRecord([string]$source, [string]$rawRecord) {
        $this.rawRecord = $rawRecord
        $this.Version = 'spf1'
        $this.FinalAction = [SpfAction]::Neutral
        $this.Source = $source
        $this.Entries = @()
    }

    [string] ToString() {
        return "Source: $($this.Source) Record: $($this.rawRecord)"
    }

    static [SpfRecord[]] Parse([string]$source, [string]$rawRecord) {
        $retVal = @()
        $record = [SpfRecord]::new($source, $rawRecord)
        $retVal += $record

        $parts = $rawRecord.Split(' ')
        $continueParsing = $true

        foreach($part in $parts)
        {
            if($part.StartsWith('v='))
            {
                $record.Version = $part.Substring(2)
            }
            #methods
            elseif ($continueParsing -and ($part.StartsWith('ip4:') -or $part.StartsWith('ip6:')))
            {
                $ip = $part.Substring(4)
                $prefix = $part.Substring(0, 3)
                $record.Entries += [SpfEntry]::new($source, $prefix, $ip)
                if($ip -match '/')
                {
                    $record.Entries += [SpfIpNetwork]::Parse($source, $ip)
                }
                else
                {
                    $record.Entries += [SpfIpAddress]::Parse($source, $ip)
                }
            }
            elseif($continueParsing -and $part.StartsWith('include:'))
            {
                $domainName = $part.Substring(8)
                $record.Entries += [SpfEntry]::new($source, 'include', $domainName)
                if($retval.source -notcontains $domainName)
                {
                    $additionalRecords = [Dns]::GetSpfRecord($domainName)
                    foreach($additionalRecord in $additionalRecords)
                    {
                        $retVal += [SpfRecord]::Parse($domainName, $additionalRecord)
                    }
                }
                else
                {
                    Write-Warning "Cyclic reference: $domainName"
                }
            }
            elseif($continueParsing -and $part.StartsWith('exists:') -or $part.StartsWith('ptr:') -or $part -eq 'ptr')
            {
                $splits = $part.Split(':')
                if($splits.Length -gt 1)
                {
                    $record.Entries += [SpfEntry]::new($source, $splits[0], $splits[1])
                }
                else
                {
                    $record.Entries += [SpfEntry]::new($source, $part, $null)
                }
            }
            elseif($continueParsing -and ($part.StartsWith('a:') -or $part.StartsWith('a/') -or $part -eq 'a' -or $part.StartsWith('+a:') -or $part.StartsWith('+a/') -or $part -eq '+a'))
            {
                $mask = -1
                $splits = $part.Split('/')
                if($splits.Length -gt 1)
                {
                    if(-not [int]::TryParse($splits[1], [ref]$mask))
                    {
                        Write-Warning "Invalid mask value in $part"
                    }
                }
                $splits = $splits[0].Split(':')
                $domainName = $source
                if($splits.Length -gt 1)
                {
                    $domainName = $splits[1]
                }
                $start = 1
                if($part[0] -eq '+')
                {
                    $start++
                }

                $record.Entries += [SpfEntry]::new($source, 'a', $part.Substring($start).Replace(':',''))
                if($mask -eq -1)
                {
                    [SpfRecord]::ParseAMechanism($domainName, $part, [ref]$record)
                }
                else {
                    [SpfRecord]::ParseAWithMaskMechanism($domainName, $mask, $part, [ref]$record)
                }
            }
            elseif($continueParsing -and ($part.StartsWith('mx') -or $part.startsWith('+mx')))
            {
                $mask = -1
                $splits = $part.Split('/')
                if($splits.Length -gt 1)
                {
                    if(-not [int]::TryParse($splits[1], [ref]$mask))
                    {
                        Write-Warning "Invalid mask value in $part"
                    }
                }
                $splits = $splits[0].Split(':')
                $domainName = $source
                if($splits.Length -gt 1)
                {
                    $domainName = $splits[1]
                }
                $start = 2
                if($part[0] -eq '+')
                {
                    $start++
                }
                $record.Entries += [SpfEntry]::new($source, 'mx', $part.Substring($start).Replace(':',''))

                $mx = [Dns]::GetRecord($domainName, [DnsClient.QueryType]::MX)
                foreach($rec in $mx)
                {
                    if($null -eq $rec) {continue}
                    $domainName = $rec -as [string]
                    if($null -eq $domainName) {continue}
                    if($mask -eq -1)
                    {
                        [SpfRecord]::ParseAMechanism($domainName, $part, [ref]$record)
                    }
                    else {
                        [SpfRecord]::ParseAWithMaskMechanism($domainName, $mask, $part, [ref]$record)
                    }
                }
            }
            elseif($part -eq 'all' -or $part -eq '+all')
            {
                $record.FinalAction = [SpfAction]::Pass
                $continueParsing = $false
            }
            elseif($part -eq '-all')
            {
                $record.FinalAction = [SpfAction]::Fail
                $continueParsing = $false
            }
            elseif($part -eq '~all')
            {
                $record.FinalAction = [SpfAction]::SoftFail
                $continueParsing = $false
            }
            elseif($part -eq '?all')
            {
                $record.FinalAction = [SpfAction]::Neutral
                $continueParsing = $false
            }
            #Modifiers
            elseif($part.StartsWith('redirect='))
            {
                $domainName = $part.Substring(9)
                $record.Entries += [SpfEntry]::new($source, 'redirect', $domainName)
                $additionalRecords = [Dns]::GetSpfRecord($domainName)
                foreach($additionalRecord in $additionalRecords)
                {
                    $retVal += [SpfRecord]::Parse($domainName, $additionalRecord)
                }
            }
            elseif($part.StartsWith('exp='))
            {
                $domainName = $part.Substring(4)
                $record.Entries += [SpfEntry]::new($source, 'exp', $domainName)
            }
        }
        
        return $retVal
    }

    static [void] ParseAMechanism([string]$domain, [string]$rawEntry, [ref]$record) {
        $records = [Dns]::GetRecord($domain, [DnsClient.QueryType]::A)
        $records += [Dns]::GetRecord($domain, [DnsClient.QueryType]::AAAA)
        foreach($rec in $records)
        {
            if($null -eq $rec) {continue}
            $ip = $rec -as [System.Net.IPAddress]
            if($null -eq $ip) {continue}
            $record.Entries += [SpfIpAddress]::new("$domain $rawEntry", $ip)
        }
    }

    static [void] ParseAWithMaskMechanism([string]$domain, [int]$mask, [string]$rawEntry, [ref]$record) {
        $records = [Dns]::GetRecord($domain, [DnsClient.QueryType]::A)
        $records += [Dns]::GetRecord($domain, [DnsClient.QueryType]::AAAA)
        foreach($rec in $records)
        {
            if($null -eq $rec) {continue}
            $ip = $rec -as [System.Net.IPAddress]
            if($null -eq $ip) {continue}
            $record.Entries += [SpfIpNetwork]::new("$domain $rawEntry", $ip, $mask)
        }
    }
}
#endregion Classes
#region Public commands
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
        [SpfRecord]$SpfRecord,
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'DomainName')]
        [string]$Domain
    )

    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'DomainName')
        {
            Write-Verbose "Processing $Domain"
            [SpfRecord[]]$record = Get-SpfRecord -Domain $Domain `
        }
        else
        {
            $record = $SpfRecord
        }
        Write-Verbose "Processing $record"
        $record.Entries | Where-Object{$_ -is [SpfEntry]}
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
        [SpfRecord]$SpfRecord,
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'DomainName')]
        [string]$Domain
    )

    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'DomainName')
        {
            Write-Verbose "Processing $Domain"
            [SpfRecord[]]$record = Get-SpfRecord -Domain $Domain 
        }
        else
        {
            $record = $SpfRecord
        }

        Write-Verbose "Processing $record"
        $record.Entries | Where-Object { $_ -is [SpfIpAddress] }
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
        [SpfRecord]$SpfRecord,
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'DomainName')]
        [string]$Domain
    )

    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'DomainName')
        {
            Write-Verbose "Processing $Domain"
            [SpfRecord[]]$record = Get-SpfRecord -Domain $Domain 
        }
        else
        {
            $record = $SpfRecord
        }

        Write-Verbose "Processing $record"
        $record.Entries | Where-Object { $_ -is [SpfIpNetwork] }
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
        [SpfRecord]$SpfRecord,
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'DomainName')]
        [string]$Domain,
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
            [SpfRecord[]]$spfRecords = Get-SpfRecord -Domain $Domain `
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
                        $additionalRecord = [SpfRecord]::Parse($_.Source, $rawRecord)
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
Get-SpfRecord -Domain 'mydomain.com' -RawRecord 'v=spf1 include:spf.protection.outlook.com -all'
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

    process
    {
        [SpfRecord]::Parse($Domain, $RawRecord)
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
            $dottedIp = [IpHelper.IPAddressExtensions]::ToDotted($IpAddress)
            $macro = $macro -replace '%{i}', $dottedIp
        }
        if($macro -match '%{ir}') {
            $dottedIp = [IpHelper.IPAddressExtensions]::ToReverseDotted($IpAddress)
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
