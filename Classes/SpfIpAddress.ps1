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
            $ip = [System.Net.IPAddress]::Parse($address)
            return [SpfIpAddress]::new($source, $ip)
    }
}
