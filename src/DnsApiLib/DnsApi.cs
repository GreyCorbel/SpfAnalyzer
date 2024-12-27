namespace DnsApi
{
    using System;
    using System.Collections.Generic;
    using System.Runtime.InteropServices;
    using System.ComponentModel;
    using System.Linq;
    using static DnsApi.Native;
    using System.Net;
    using System.Text;
    using System.Threading.Tasks;

    public class Domain
    {
        private static readonly char[] _spfSeparator = [':', '='];
        static List<object> GetRecord(string record, QueryTypes recordType)
        {
            IntPtr results = IntPtr.Zero;
            try
            {
                List<object> retVal = new List<object>();
                var err = DnsQuery($"{record}", recordType, QueryOptions.DNS_QUERY_STANDARD, IntPtr.Zero, ref results);
                if (err == 0)
                {
                    IntPtr ptr = results;
                    do
                    {
                        switch (recordType)
                        {
                            case QueryTypes.DNS_TYPE_A:
                                {
                                    var rec = Marshal.PtrToStructure<ARecord>(ptr);
                                    retVal.Add(new IPAddress(rec.data.ipAddressData));
                                    ptr = rec.hdr.pNext;
                                    break;
                                }
                            case QueryTypes.DNS_TYPE_MX:
                                {
                                    var rec = Marshal.PtrToStructure<PtrRecord>(ptr);
                                    retVal.Add(rec.data.pNameHost);
                                    ptr = rec.hdr.pNext;
                                    break;
                                }
                            case QueryTypes.DNS_TYPE_SRV:
                                {
                                    var rec = Marshal.PtrToStructure<SRVRecord>(ptr);
                                    DNS_SRV_DATA srv = rec.srv;
                                    retVal.Add(srv);
                                    ptr = rec.hdr.pNext;
                                    break;
                                }
                            case QueryTypes.DNS_TYPE_TEXT:
                                {
                                    var txtRecord = Marshal.PtrToStructure<TxtRecord>(ptr);
                                    StringBuilder sb = new StringBuilder();
                                    for (int i = 0; i<txtRecord.data.dwStringCount; i++)
                                    {
                                        sb.Append(txtRecord.data.data[i]);
                                    }
                                    retVal.Add(sb.ToString());
                                    ptr = txtRecord.hdr.pNext;
                                    break;
                                }
                            case QueryTypes.DNS_TYPE_CNAME:
                                {
                                    var rec = Marshal.PtrToStructure<PtrRecord>(ptr);
                                    retVal.Add(rec.data.pNameHost);
                                    ptr = rec.hdr.pNext;
                                    break;
                                }
                            case QueryTypes.DNS_TYPE_NS:
                                {
                                    var rec = Marshal.PtrToStructure<PtrRecord>(ptr);
                                    retVal.Add(rec.data.pNameHost);
                                    ptr = rec.hdr.pNext;
                                    break;
                                }
                                case QueryTypes.DNS_TYPE_AAAA:
                                {
                                    var rec = Marshal.PtrToStructure<AaaaRecord>(ptr);
                                    UInt128 uInt128 = rec.data.ipAddressData;
                                    var buff = MemoryMarshal.AsBytes(new Span<UInt128>(ref uInt128));
                                    retVal.Add(new IPAddress(buff));
                                    ptr = rec.hdr.pNext;
                                    break;
                                }

                            default:
                                throw new NotImplementedException($"Record type {recordType} is not implemented");
                        }
                    } while (ptr != IntPtr.Zero);
                    return retVal;
                }

                //return empty results if entry not found
                if (err == (int)DnsError.NameNotFound || err == (int)DnsError.NoRecordsFound)
                    return retVal;

                //throw if other error
                throw new Win32Exception(err);
            }
            finally
            {
                if (results != IntPtr.Zero)
                    DnsFree(results, DNS_FREE_TYPE.DnsFreeRecordList);
            }
        }

        public static bool IsDomainRegistered(string domain)
        {
            IntPtr results = IntPtr.Zero;
            try
            {
                var err = DnsQuery($"{domain}", QueryTypes.DNS_TYPE_SOA, QueryOptions.DNS_QUERY_STANDARD, IntPtr.Zero, ref results);
                //SOA may also be a CNAME - see hrms.bipocloud.com
                var validSoaTypes = new[] { (ushort)QueryTypes.DNS_TYPE_SOA, (ushort)QueryTypes.DNS_TYPE_CNAME };
                if (err == 0)
                {
                    IntPtr ptr = results;
                    ushort soaTypeFound = 0;
                    do
                    {
                        SoaRecord record = Marshal.PtrToStructure<SoaRecord>(ptr);
                        soaTypeFound = record.hdr.wType;
                        if (validSoaTypes.Any(x => x == soaTypeFound))
                            return true;

                        ptr = record.hdr.pNext;
                    } while (ptr != IntPtr.Zero);

                    //safety net - we found something but not SOA or CNAME
                    return true;
                }

                if (err == (int)DnsError.NameNotFound)
                    return false;

                //DnsError.NoRecordsFound occurs when domain does not have own DNS zone --> we assume that domain exists
                if (err == (int)DnsError.NoRecordsFound)
                    return true;

                if (err == (int)DnsError.InvalidName)    //incorrect volume label
                    throw new ArgumentException($"Domain name {domain} did not pass validation on DNS API level");

                throw new Win32Exception(err);
            }
            finally
            {
                if (results != IntPtr.Zero)
                    DnsFree(results, DNS_FREE_TYPE.DnsFreeRecordList);
            }
        }

        protected static void ParseIpNetwork(string domain, string rawEntry, ref SpfRecord record)
        {
            if (rawEntry.Contains("/"))
            {
                IPNetwork parsed;
                if (IPNetwork.TryParse(rawEntry, out parsed))
                    record.Entries.Add(new SpfIpNetwork(domain, parsed));
                else
                    record.Entries.Add(
                        new SpfEntryInvalidNetwork()
                        {
                            Value = rawEntry
                        });
            }
            else
            {
                if (SpfIpAddress.TryParse(domain, rawEntry, out SpfIpAddress? parsed) && parsed is not null)
                    record.Entries.Add(parsed);
                else
                    record.Entries.Add(
                        new SpfEntryInvalidAddress()
                        {
                            Value = rawEntry
                        });
            }
        }

        protected static void ParseAMechanism(string domain, string rawEntry, ref SpfRecord record)
        {
            var results = GetRecord(domain, QueryTypes.DNS_TYPE_A);
            results.AddRange(GetRecord(domain, QueryTypes.DNS_TYPE_AAAA));

            foreach (var rec in results)
            {
                if (rec is null)
                    continue;
                var entry = rec as IPAddress;
                if (entry != null)
                {
                    //no prefix, just IP address
                    record.Entries.Add(new SpfIpAddress($"{domain} {rawEntry}", entry));
                }
            }
        }

        protected static void ParseAWithMaskMechanism(string domain, int mask, string rawEntry, ref SpfRecord record)
        {
            var results = GetRecord(domain, QueryTypes.DNS_TYPE_A);
            results.AddRange(GetRecord(domain, QueryTypes.DNS_TYPE_AAAA));

            foreach (var rec in results)
            {
                if (rec is null)
                    continue;
                var entry = rec as IPAddress;
                if (entry != null)
                {
                    record.Entries.Add(new SpfIpNetwork($"{domain} {rawEntry}", entry, mask));
                }
            }
        }
        public static List<SpfRecord> ParseSpfRecord(string domain, string rawRecord)
        {
            List<SpfRecord> records = new List<SpfRecord>();

            SpfRecord record = new SpfRecord(domain, rawRecord);
            records.Add(record);
            var parts = rawRecord.Split(' ');
            bool mechanismParsingCompleted = false;
            foreach (var part in parts)
            {
                if (part.StartsWith("v="))
                    record.Version = part[2..];
                #region Mechanisms
                else if (!mechanismParsingCompleted && (part.StartsWith("ip4:") || part.StartsWith("ip6:")))
                {
                    ParseIpNetwork(domain, part[4..], ref record);
                }
                else if (!mechanismParsingCompleted && part.StartsWith("include:"))
                {
                    var domainName = part[8..];
                    record.Entries.Add(new SpfEntryInclude() { Value = domainName });
                    List<SpfRecord>? inc = GetSpfRecord(domainName);
                    if (null != inc)
                        records.AddRange(inc);
                }
                else if (!mechanismParsingCompleted && (part.StartsWith("exists:")  || part.StartsWith("ptr:") || part == "ptr"))
                {
                    //we just add entry for mechanism presence, but do not parse it
                    var splits = part.Split(_spfSeparator);
                    record.Entries.Add(new SpfEntryOther()
                    {
                        Prefix = splits[0],
                        Value = splits.Length > 1 ? splits[1] : null
                    });
                }
                else if (!mechanismParsingCompleted && (part == "a" || part.StartsWith("a:") || part.StartsWith("a/")))
                {
                    //get prefix length if it's there
                    var splits = part.Split('/');
                    string? prefix = splits.Length > 1 ? splits[1] : null;
                    int mask = -1;
                    if (prefix is not null && !int.TryParse(prefix, out mask))
                    {
                        record.Entries.Add(new SpfEntryInvalidNetwork() { Value = part });
                    }
                    else
                    {
                        //get domain if it's there
                        splits = splits[0].Split(':');
                        var domainName = splits.Length > 1 ? splits[1] : domain;
                        record.Entries.Add(new SpfEntryOther()
                        {
                            Prefix = "a",
                            Value = $"{part.Substring(1).Replace(":", string.Empty)}"
                        });

                        if (mask == -1)
                        {
                            ParseAMechanism(domainName, part, ref record);
                        }
                        else
                        {
                            ParseAWithMaskMechanism(domainName, mask, part, ref record);
                        }
                    }
                }
                else if (!mechanismParsingCompleted && (part == "mx" || part.StartsWith("mx:") || part.StartsWith("mx/")))
                {

                    //get prefix length if it's there
                    var splits = part.Split('/');
                    string? prefix = splits.Length > 1 ? splits[1] : null;
                    int mask = -1;
                    if (prefix is not null && !int.TryParse(prefix, out mask))
                    {
                        record.Entries.Add(new SpfEntryInvalidNetwork() { Value = part });
                    }
                    else
                    {
                        //get domain if it's there
                        splits = splits[0].Split(':');
                        var domainName = splits.Length > 1 ? splits[1] : domain;
                        record.Entries.Add(new SpfEntryOther()
                        {
                            Prefix = "mx",
                            Value = $"{part.Substring(2).Replace(":", string.Empty)}"
                        });

                        var mx = GetRecord(domainName, QueryTypes.DNS_TYPE_MX);

                        foreach(var rec in mx)
                        {
                            if(rec is null)
                                continue;
                            var entry = rec as string;
                            if(entry is null)
                                continue;

                            if (mask == -1)
                            {
                                ParseAMechanism(entry, part, ref record);
                            }
                            else
                            {
                                ParseAWithMaskMechanism(entry, mask, part, ref record);
                            }
                        }
                    }
                }
                //final actions
                //actions are terminating --> we do not parse anything after them
                else if (part == "all" || part == "+all")
                {
                    record.FinalAction = SpfAction.Pass;
                    mechanismParsingCompleted = true;
                }
                else if (part == "-all")
                {
                    record.FinalAction = SpfAction.Fail;
                    mechanismParsingCompleted = true;
                }
                else if (part == "~all")
                {
                    record.FinalAction = SpfAction.SoftFail;
                    mechanismParsingCompleted = true;
                }
                else if (part == "?all")
                {
                    record.FinalAction = SpfAction.Neutral;
                    mechanismParsingCompleted = true;
                }

                #endregion
                #region Modifiers
                else if (part.StartsWith("redirect="))
                {
                    var domainName = part[9..];
                    record.Entries.Add(new SpfEntryRedirect() { Value = domainName });
                    List<SpfRecord>? inc = GetSpfRecord(domainName);
                    if (null != inc)
                        records.AddRange(inc);
                }
                else if (part.StartsWith("exp="))
                {
                    var domainName = part[4..];
                    var expRecord = GetRecord(domainName, QueryTypes.DNS_TYPE_TEXT);
                    if (expRecord != null && expRecord.Any())
                    {
                        record.Entries.Add(
                            new SpfEntryExplain()
                            {
                                Value = expRecord.First().ToString()
                            });
                    }
                }
                #endregion
            }
            return records;
        }
        public static List<SpfRecord>? GetSpfRecord(string domain)
        {
            var data = GetRecord(domain, QueryTypes.DNS_TYPE_TEXT);
            if (data == null || data.Count == 0)
                return null;

            string? rawRecord = data.Where(x=> x is not null).FirstOrDefault(x => x.ToString().StartsWith("v=spf"))?.ToString();
            if (rawRecord == null)
                return null;

            return ParseSpfRecord(domain, rawRecord);
        }

        
    }
}

