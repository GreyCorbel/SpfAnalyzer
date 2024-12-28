# SPF record analyzer
This is repor for development of SPFAnalyzer powershell module. Module provides commands that help retrieve data that define security policy for sending mail for Authorizing Use of Domains in Email.  
# Usage

## Getting and parsing 
Command below retrieves all SPF data the records published by given domain:
```powershell
Get-SPFRecord -Domain microsoft.com
```
Returns parsed SPF record for domain, and all records specified by `include:` or `redirect=` entries. Command above returns the following:
```
Version FinalAction Source                         Entries
------- ----------- ------                         -------
spf1    Fail        microsoft.com                  {include _spf-a.microsoft.com, include _spf-b.microsoft.com, include _spf-c.microsoft.com, include _spf-ssg-a.msft.net…}
spf1    SoftFail    _spf-a.microsoft.com           {216.99.5.67, 216.99.5.68, 202.177.148.100, 203.122.32.250…}
spf1    Fail        spf.protection.outlook.com     {40.92.0.0/15, 40.107.0.0/16, 52.100.0.0/15, 52.102.0.0/16…}
spf1    SoftFail    _spf-b.microsoft.com           {include _spf-mdm.microsoft.com, 207.46.22.35, 207.46.22.96/29, 217.77.141.52…}
spf1    Fail        _spf-mdm.microsoft.com         {134.170.113.0/26, 131.253.30.0/24, 157.56.120.128/26, 134.170.174.0/24…}
spf1    SoftFail    _spf-c.microsoft.com           {213.199.138.181, 213.199.138.191, 207.46.52.71, 207.46.52.79…}
spf1    SoftFail    _spf-ssg-a.msft.net            {104.44.112.128/25, 134.170.27.8, 157.58.30.128/25, 20.63.210.192/28…}
spf1    SoftFail    spf-a.hotmail.com              {157.55.0.192/26, 157.55.1.128/26, 157.55.2.0/25, 65.54.190.0/24…}
spf1    SoftFail    _spf1-meo.microsoft.com        {52.235.253.128, 20.141.10.196, 20.118.139.208/30, 20.98.194.68/30…}
```
Output is parsed, and each entry shows in its `Source` field where it came from (domain, or record specified by `include` mechanism or `redirect` modifier)

## Testing the IP address against published policy
Command below tests IP address against policy published by domain and returns all mathing entries. During testing, macros specified in `exists` mechanism are expanded and queries performed.
```powershell
Test-SpfHost -Domain microsoft.com -IpAddress 104.44.112.224
```
Command returns matching entries as below - when at least 1 entry is returned, then IP address is authorized for use of domain in email. Again, `Source` field in returned entries shows, which SPF mechanism authorized the IP address.
```
Source                         BaseAddress               PrefixLength
------                         -----------               ------------
_spf-ssg-a.msft.net            104.44.112.128            25
```

## Modelling and testing SPF record
Module allows passing raw SPF record and parse it, and possibly test against IP addresses and Sender email to see if policy works as expected.
```powershell
Test-SpfRecord `
    -RawRecord 'v=spf1 include:_spf-a.microsoft.com include:_spf-b.microsoft.com include:_spf-c.microsoft.com include:_spf-ssg-a.msft.net include:spf-a.hotmail.com include:_spf1-meo.microsoft.com -all' `
    -Domain microsoft.com `
| Test-SpfHost -IpAddress 104.44.112.128 
```

# Features and limitations
Module is cross-platform and relies on DnsClient.NET package.  
Module provides additional heler commands that return list of IP addresses and IP subnets found in publshed policy.  
IPv4 and IPv6 addresses are supported.  
Only Powershell Core edition is supported.  
Macro expansion in `exists` mechanism does not yet cover complete specification in RFC 7208 - looking for collaborators to enhance parsing.

