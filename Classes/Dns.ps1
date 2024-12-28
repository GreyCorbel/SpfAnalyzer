class Dns {
    [string]$Name

    Dns([string]$name) {
        $this.Name = $name
    }

    static [object[]] GetRecord([string]$Name, [Microsoft.DnsClient.Commands.RecordType]$recordType) {
        $retVal = @()
        switch($recordType)
        {
            {$_ -in ([Microsoft.DnsClient.Commands.RecordType]::A,[Microsoft.DnsClient.Commands.RecordType]::A_AAAA, [Microsoft.DnsClient.Commands.RecordType]::AAAA)} { 
                $data = Resolve-DnsName -Name $Name -Type $_ | select-object -ExpandProperty IPAddress
                $data | where-object{$_ -ne $null} | foreach-object {
                    try {
                        $retVal += [SpfIpAddress]::Parse($recordName, $_)
                    }
                    catch {
                        Write-Warning "Failed to parse $_ as IP address"
                    }
                }
                break;
            }
            {$_ -eq [Microsoft.DnsClient.Commands.RecordType]::MX} {
                $data = Resolve-DnsName -Name $Name -Type MX | select-object -ExpandProperty NameExchange
                $data | where-object{$_ -ne $null} | foreach-object {
                    $retVal += $_
                }
                break;
            }
            {$_ -eq [Microsoft.DnsClient.Commands.RecordType]::TXT} {
                $data = Resolve-DnsName -Name $Name -Type TXT | select-object -ExpandProperty Strings
                $data | where-object{$_ -ne $null} | foreach-object {
                    $retVal += $_
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
        $data = Resolve-DnsName -Name $Name -Type TXT | select-object -ExpandProperty Strings
        $data | where-object{$_ -ne $null} | foreach-object {
            if($_ -match "^v=spf1") {
                $retVal += $_
            }
        }
        if($retVal.Count -eq 0) {return $null} else {return $retVal}
    }
}
