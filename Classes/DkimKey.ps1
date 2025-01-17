class DkimKey {
    [string]$SignatureAlgorithm
    [int]$KeySize


    DkimKey([string]$algorithm, [int]$keySize) {
        $this.SignatureAlgorithm = $algorithm
        $this.KeySize = $keySize
    }

    [string] ToString() {
        return "Algo: $($this.SignatureAlgorithm) KeySize: $($this.KeySize)"
    }

    static [DkimKey] Parse([string]$algo, [string]$encodedKey) {
        $retVal = [DkimKey]::new($algo, 0)
        try {
            switch($algo) {
                'rsa' {
                    $rsa = [System.Security.Cryptography.RSA]::Create()
                    $rsa.ImportSubjectPublicKeyInfo([Convert]::FromBase64String($encodedKey), [ref]$null)
                    $retVal.keySize = $rsa.KeySize
                    $retVal.SignatureAlgorithm = $rsa.SignatureAlgorithm
                    break;
                }
                'ed25519' {
                    #we want to parse to detect invalid data in DNS records
                    $publicKey = [Convert]::FromBase64String($encodedKey)
                    $retVal.KeySize = $publicKey.Length * 8
                    $retVal.SignatureAlgorithm = 'Ed25519'
                    break;
                }
                default {
                    Write-Warning "Unknown algo: $algo"
                    $retVal.KeySize = -1
                }
            }
        }
        catch {
            Write-Warning "Invalid key: $encodedKey`nError: $($_.Exception.Message)"
            $retVal.KeySize = -2
        }
        return $retVal
    }
}
