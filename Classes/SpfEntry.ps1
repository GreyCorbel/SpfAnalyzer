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