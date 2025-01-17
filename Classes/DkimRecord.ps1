class DkimRecord {
    hidden [string] $rawRecord
    [string] $Version
    [string]$Domain
    [string] $Source
    [DkimKey] $PublicKey
    [object[]] $Entries


    DkimRecord([string]$domain, [string]$source, [string]$rawRecord) {
        $this.RawRecord = $rawRecord
        $this.Version = 'DKIM1'
        $this.Domain = $domain
        $this.Source = $source
        $this.Entries = @()

    }

    [string] ToString() {
        return "Source: $($this.Source) Record: $($this.rawRecord)"
    }

    static [DkimRecord[]] Parse([string]$domain, [string]$Source, [string]$rawRecord)
    {
        [string[]]$tags = @('v=', 'h=', 'k=', 'n=', 'p=', 's=','t=', 'o=')

        $retVal = @()
        $record = [DkimRecord]::new($Domain, $source, $rawRecord)
        $retVal += $record

        $parts = $rawRecord.Split(';')
        $algo = 'rsa'
        $key = ''

        foreach($part in $parts)
        {
            $token = $part.Trim()
            if($token.Length -eq 0) {continue}

            $tag = $token.Substring(0,2)
            if($tag -eq 'v=')
            {
                #split is there because some DKIM entries are filled in by SPF data
                $record.Version = $token.Substring(2).Split(' ')[0]
            }
            elseif($tag -in $tags)
            {
                $record.Entries += [DkimEntry]::new($source, $token.Substring(0,1), $token.Substring(2))
                if($tag -eq 'k=')
                {
                    $algo = $token.Substring(2)
                }
                elseif($tag -eq 'p=')
                {
                    $key = $token.Substring(2)
                }
            }
            else {
                #possible key without tag? e.g. salesforce20161220._domainkey.dhl.com.
                $record.Entries += [DkimEntry]::new($source, 'p?', $token)
                #$key = $token
            }
        }
        if(-not [string]::IsNullOrEmpty($key))
        {
            $record.PublicKey =  [DkimKey]::Parse($algo, $key)
        }
        return $record
    }
}