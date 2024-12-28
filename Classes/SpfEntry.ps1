class SpfEntry {
    [string]$Prefix
    [string]$Value

    SpfEntry([string]$prefix, [string]$value) {
        $this.Prefix = $prefix
        $this.Value = $value
    }

    [string] ToString() {
        return "$($this.Prefix) $($this.Value)"
    }
}