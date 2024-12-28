function Get-SpfRecordEntries
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Record')]
        [SpfRecord]$SpfRecord,
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'DomainName')]
        [string]$Domain,
        [switch]$IncludeIpAddresses,
        [switch]$IncludeIpNetworks
    )

    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'DomainName')
        {
            Write-Verbose "Processing $Domain"
            [SpfRecord[]]$record = Get-SpfRecord -Domain $Domain `
        }
        else
        {
            $record = $SpfRecord
        }
        Write-Verbose "Processing $record"
        $record.Entries | Where-Object{$_ -is [SpfEntry]}
        if($IncludeIpAddresses)
        {
            $record.Entries | Where-Object{$_ -is [SpfIpAddress]}
        }
        if($IncludeIpNetworks)
        {
            $record.Entries | Where-Object{$_ -is [SpfIpNetwork]}
        }
    }    
}