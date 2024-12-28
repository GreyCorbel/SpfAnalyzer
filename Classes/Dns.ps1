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
