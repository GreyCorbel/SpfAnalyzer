using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SpfAnalyzer
{
    public enum SpfAction
    {
        Pass,
        Fail,
        SoftFail,
        Neutral
    }
    public class SpfRecord
    {
        string? _rawRecord;
        List<SpfIpAddress> _ipAddresses = new List<SpfIpAddress>();
        List<SpfIpNetwork> _ipNetworks = new List<SpfIpNetwork>();
        List<SpfEntry> _entries = new List<SpfEntry>();

        public string Version { get; set; }
        public SpfAction FinalAction { get; set; }
        public string? Source { get; set; }
        public string? Domain { get; set; }
        public int Depth { get; set; } = 0;
        public SpfEntry[] Entries
        {
            get
            {
                return _entries.ToArray();
            }
        }

        public SpfIpAddress[] IpAddresses
        {
            get
            {
                return _ipAddresses.ToArray();
            }
        }
        public SpfIpNetwork[] IpNetworks
        {
            get
            {
                return _ipNetworks.ToArray();
            }
        }

        public override string ToString()
        {
            return _rawRecord ?? string.Empty;
        }
        public SpfRecord()
        {
            Version = "spf1";
            FinalAction = SpfAction.Neutral;
        }
        public SpfRecord(string source, string domain, string rawRecord)
        {
            Source = source;
            Domain = domain;
            _rawRecord = rawRecord;
            Version = "spf1";
            FinalAction = SpfAction.Neutral;

        }

        public static bool TryParse(Dns dns, string domain, string source, string rawRecord, int depth, ILogger? logger, out SpfRecord[] spfRecords)
        {
            logger?.LogVerbose($"Parsing SPF record: {rawRecord}");
            var record = new SpfRecord(source, domain, rawRecord);
            record.Depth = depth;
            var retVal = new List<SpfRecord>();
            retVal.Add(record);

            var parts = rawRecord.Split(' ');
            if (parts.Length < 2)
            {
                logger?.LogWarning($"Invalid SPF record: {rawRecord}");
                spfRecords = Array.Empty<SpfRecord>();
                return false;
            }

            bool continueParsing = true;
            foreach (var part in parts)
            {
                if (part.StartsWith("v="))
                {
                    record.Version = part.Substring(2);
                }
                else if (continueParsing && (part.StartsWith("ip4:") || part.StartsWith("ip6:")))
                {
                    var ip = part.Substring(4);
                    var prefix = part.Substring(0, 3);
                    record._entries.Add(new SpfEntry(domain, source, prefix, ip));
                }
                else if (continueParsing && part.StartsWith("include:"))
                {
                    var includeDomain = part.Substring(8);
                    record._entries.Add(new SpfEntry(domain, source, "include", includeDomain));
                    //prevent infinite recursion
                    if (retVal.Where(x => string.Equals(x.Source, includeDomain, StringComparison.OrdinalIgnoreCase)).Count() == 0)
                    {
                        var additionalRecords = dns.GetSpfRecord(includeDomain);
                        foreach (var additionalRecord in additionalRecords)
                        {
                            if( TryParse(dns, domain, includeDomain, additionalRecord, record.Depth + 1, logger, out SpfRecord[] additionalSpfRecord))
                                retVal.AddRange(additionalSpfRecord);
                        }
                    }
                    else
                    {
                        logger?.LogWarning($"Infinite recursion detected for domain: {includeDomain}");
                    }
                }
                else if (continueParsing && (part.StartsWith("exists:") || part.StartsWith("ptr:") || part.StartsWith("ptr")))
                {
                    var splits = part.Split(':');
                    if (splits.Length > 1)
                        record._entries.Add(new SpfEntry(domain, source, splits[0], splits[1]));
                    else
                    {
                        record._entries.Add(new SpfEntry(domain, source, splits[0], string.Empty));
                    }
                }
                else if (continueParsing && (part.StartsWith("a:") || part.StartsWith("a/") || part.Equals("a") || part.StartsWith("+a:") || part.StartsWith("+a/") || part.Equals("+a")))
                {
                    var mask = -1;
                    var splits = part.Split('/');
                    if (splits.Length > 1)
                    {
                        int.TryParse(splits[1], out mask);
                    }
                    splits = splits[0].Split(':');
                    var domainName = source;
                    if (splits.Length > 1)
                    {
                        domainName = splits[1];
                    }
                    var start = 1;
                    if (splits[0].StartsWith("+"))
                    {
                        start = 2;
                    }
                    record._entries.Add(new SpfEntry(domain, source, "a", part.Substring(start).Replace(":", string.Empty)));
                    if (mask > -1)
                    {
                        ParseAWithMaskMechanism(dns, domainName, $"{domainName} {part}", mask, ref record);
                    }
                    else
                    {
                        ParseAMechanism(dns, domainName, $"{domainName} {part}", ref record);
                    }
                }
                else if (continueParsing && (part.StartsWith("mx") || part.StartsWith("+mx")))
                {
                    var mask = -1;
                    var splits = part.Split('/');
                    if (splits.Length > 1)
                    {
                        int.TryParse(splits[1], out mask);
                    }
                    splits = splits[0].Split(':');
                    var domainName = source;
                    if (splits.Length > 1)
                    {
                        domainName = splits[1];
                    }
                    var start = 2;
                    if (splits[0].StartsWith("+"))
                    {
                        start = 3;
                    }
                    record._entries.Add(new SpfEntry(domain, source, "mx", part.Substring(start).Replace(":", string.Empty)));
                    var mx = dns.GetRecord(domain, DnsClient.QueryType.MX);
                    foreach (var rec in mx)
                    {
                        if (rec is string)
                        {
                            var mxDomain = (string)rec;
                            if (mask == -1)
                                ParseAMechanism(dns, mxDomain, $"{mxDomain} {part}", ref record);
                            else
                                ParseAWithMaskMechanism(dns, mxDomain, $"{mxDomain} {part}", mask, ref record);
                        }
                    }
                }
                else if (continueParsing && (part.StartsWith("all") || part.StartsWith("+all")))
                {
                    record.FinalAction = SpfAction.Pass;
                    continueParsing = false;
                }
                else if (continueParsing && part.Equals("-all"))
                {
                    record.FinalAction = SpfAction.Fail;
                    continueParsing = false;
                }
                else if (continueParsing && part.Equals("~all"))
                {
                    record.FinalAction = SpfAction.SoftFail;
                    continueParsing = false;
                }
                else if (continueParsing && part.Equals("?all"))
                {
                    record.FinalAction = SpfAction.Neutral;
                    continueParsing = false;
                }
                else if (continueParsing && part.StartsWith("redirect="))
                {
                    var redirectDomain = part.Substring(9);
                    record._entries.Add(new SpfEntry(domain, source, "redirect", redirectDomain));
                    var additionalRecords = dns.GetSpfRecord(redirectDomain);
                    foreach (var additionalRecord in additionalRecords)
                    {
                        if( TryParse(dns, domain, redirectDomain, additionalRecord, record.Depth + 1, logger, out var additionalSpfRecord))
                            retVal.AddRange(additionalSpfRecord);
                    }
                }
                else if (continueParsing && part.StartsWith("exp="))
                {
                    var explanation = part.Substring(4);
                    record._entries.Add(new SpfEntry(domain, source, "exp", explanation));
                }
            }
            foreach (var entry in record.Entries)
            {
                if ((entry.Prefix == "ip4" || entry.Prefix == "ip6") && entry?.Value != null)
                {
                    if(entry.Value.Contains("/"))
                    {
                        if(SpfIpNetwork.TryParse(source, entry.Value, logger, out var ipNetwork))
                            record._ipNetworks.Add(ipNetwork);
                    }
                    else
                    {
                        if (SpfIpAddress.TryParse(source, entry.Value, logger, out var ipAddress))
                            record._ipAddresses.Add(ipAddress);   
                    }
                }
            }
            spfRecords = retVal.ToArray();
            return true;
        }

        static void ParseAMechanism(Dns dns, string fqdn, string source, ref SpfRecord record)
        {
            var records = new List<IPAddress>();

            records.AddRange(dns.GetRecord(fqdn, DnsClient.QueryType.A).Where(x => x is IPAddress).Select(x => (IPAddress)x));
            records.AddRange(dns.GetRecord(fqdn, DnsClient.QueryType.AAAA).Where(x => x is IPAddress).Select(x => (IPAddress)x));
            foreach (var rec in records)
            {
                record._ipAddresses.Add(new SpfIpAddress(source, rec));
            }
        }

        static void ParseAWithMaskMechanism(Dns dns, string fqdn, string source, int mask, ref SpfRecord record)
        {
            var records = new List<IPAddress>();

            records.AddRange(dns.GetRecord(fqdn, DnsClient.QueryType.A).Where(x => x is IPAddress).Select(x => (IPAddress)x));
            records.AddRange(dns.GetRecord(fqdn, DnsClient.QueryType.AAAA).Where(x => x is IPAddress).Select(x => (IPAddress)x));
            foreach (var rec in records)
            {
                record._ipNetworks.Add(new SpfIpNetwork(source, rec, mask));
            }
        }
    }
}
