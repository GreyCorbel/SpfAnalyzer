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
