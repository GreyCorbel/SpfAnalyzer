function Test-SpfRecord
{
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$RawRecord,
        [Parameter(Mandatory)]
        [string]$Domain
    )

    process
    {
        [SpfRecord]::Parse($Domain, $RawRecord)
    }
}
