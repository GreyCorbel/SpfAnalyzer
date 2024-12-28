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
                $additionalRecords = [Dns]::GetSpfRecord($domainName)
                foreach($additionalRecord in $additionalRecords)
                {
                    $retVal += [SpfRecord]::Parse($domainName, $additionalRecord)
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
                $retVal+=$additionalRecords
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
