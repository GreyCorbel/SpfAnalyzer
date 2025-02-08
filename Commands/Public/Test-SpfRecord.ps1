function Test-SpfRecord
{
<#
.SYNOPSIS
    Parses raw SPF record
.DESCRIPTION
    This command parses raw SPF record and returns parsed SPF record object. This is useful when constructing SPF record from scratch to test it.
.OUTPUTS
    SpfRecord[]

.EXAMPLE
Test-SpfRecord -Domain 'mydomain.com' -RawRecord 'v=spf1 include:spf.protection.outlook.com -all'
Description
-----------
CHecks if SPF record can be parsed correctly.

.LINK
More about SPF, see http://www.openspf.org/ and https://tools.ietf.org/html/rfc7208
#>

param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$RawRecord,
        [Parameter(Mandatory)]
        [string]$Domain
    )

    begin
    {
        $logger = new-object AutomationHelper.Logger($PSCmdlet)
        $dns = new-object SpfAnalyzer.Dns
    }
    process
    {
        $parsedRecord = $null
        if([SpfAnalyzer.SpfRecord]::TryParse($dns, $Domain, $Domain, $RawRecord, 0, $logger, [ref] $parsedRecord))
        {
            $parsedRecord
        }
    }
}
