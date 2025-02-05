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