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

    public class Domain
    {
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
                                    retVal.Add(new System.Net.IPAddress(rec.data.ipAddressData).ToString());
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

        private static readonly char[] separator = new char[] { ':', '=' };

        public static List<SpfRecord>? GetSpfRecord(string domain)
        {
            var data = GetRecord(domain, QueryTypes.DNS_TYPE_TEXT);
            if (data == null || !data.Any())
                return null;

            string? rawRecord = data.FirstOrDefault(x => x != null && x.ToString().StartsWith("v=spf"))?.ToString();
            if (rawRecord == null)
                return null;

            List<SpfRecord> records = new List<SpfRecord>();

            SpfRecord record = new SpfRecord(domain, rawRecord);
            records.Add(record);
            var parts = rawRecord.Split(' ');
            foreach (var part in parts)
            {
                if (part.StartsWith("v="))
                    record.Version = part[2..];
                else if (part.StartsWith("ip4:") || part.StartsWith("ip6:"))
                {
                    var rawEntry = part[4..];
                    if (rawEntry.Contains("/"))
                    {
                        IPNetwork parsed;
                        if(IPNetwork.TryParse(rawEntry, out parsed))
                            record.Entries.Add(parsed);
                        else
                            record.Entries.Add(
                                new SpfEntryInvalidNetwork()
                                {
                                    Value = rawEntry
                                });

                    }
                    else
                    {
                        if (IPAddress.TryParse(rawEntry, out IPAddress? parsed))
                            record.Entries.Add(parsed);
                        else
                            record.Entries.Add(
                                new SpfEntryInvalidAddress()
                                {
                                    Value = rawEntry
                                });
                    }
                }
                else if (part.StartsWith("include:"))
                {
                    var domainName = part[8..];
                    record.Entries.Add(new SpfEntryInclude() { Value = domainName });
                    List<SpfRecord>? inc = GetSpfRecord(domainName);
                    if (null != inc)
                        records.AddRange(inc);
                }
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
                else if (part.StartsWith("a=") || part.StartsWith("mx=") || part.StartsWith("ptr=") || part.StartsWith("exists:") || part.StartsWith("all"))
                {
                    var splits = part.Split(separator);
                    record.Entries.Add(new SpfEntryOther()
                    {
                        Prefix = splits[0],
                        Value = splits[1]
                    });
                }
                else if (part.StartsWith("-") || part.StartsWith("~") || part.StartsWith("?") || part.StartsWith("+"))
                {
                    record.Disposition = part;
                }
            }
            return records;
        }
    }
}

