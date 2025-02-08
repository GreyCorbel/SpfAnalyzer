using DnsClient;
using System.Net;

namespace SpfAnalyzer
{
    public class Dns
    {
        LookupClient _client;

        public Dns()
        {
            _client = new LookupClient();
        }
        public Dns(string[] serverIpAddresses)
        {
            var ips = new List<IPAddress>();
            if(null != serverIpAddresses)
            {
                foreach (var ip in serverIpAddresses)
                {
                    if (IPAddress.TryParse(ip, out var ipAddr))
                    {
                        ips.Add(ipAddr);
                    }
                }
            }
            if(ips.Count > 0)
            {
                _client = new LookupClient(ips.ToArray());
            }
            else
            {
                _client = new LookupClient();
            }
        }
        public object[] GetRecord(string name, QueryType queryType)
        {
            List<object> result = new List<object>();
            
            switch (queryType)
            {
                case QueryType.A:
                case QueryType.AAAA:
                    var aRecords = _client.Query(name, queryType).AllRecords.ARecords();
                    foreach (var record in aRecords)
                    {
                        result.Add(record.Address);
                    }
                    break;
                case QueryType.TXT:
                    var question = new DnsQuestion(name, queryType);
                    var opts =  new DnsQueryAndServerOptions();
                    
                    var response = _client.Query(question, opts);
                    var txtRecords = response.AllRecords.TxtRecords();
                    foreach (var record in txtRecords)
                    {
                        result.Add(string.Join(string.Empty,record.Text));
                    }
                    break;
                case QueryType.MX:
                    var mxRecords = _client.Query(name, queryType).AllRecords.MxRecords();
                    foreach (var record in mxRecords)
                    {
                        result.Add(record.Exchange.Value);
                    }
                    break;
                case QueryType.CNAME:
                    var cnameRecords = _client.Query(name, queryType).AllRecords.CnameRecords();
                    foreach (var record in cnameRecords)
                    {
                        result.Add(record.CanonicalName.Value);
                    }
                    break;
            }
            return [.. result];
        }

        public string[] GetSpfRecord(string name)
        {
            var data = GetRecord(name, QueryType.TXT);
            List<string> result = new List<string>();
            if(null!= data)
            {
                foreach(var item in data)
                {
                    if(!(item is string))
                        continue;
                    string value = (string)item;
                    if (value.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase))
                    {
                        result.Add(value);
                    }
                }
            }
            return result.ToArray();
        }

        public DkimSource[] GetDkimRecord(string name)
        {
            var retVal = new List<DkimSource>();
            var data = GetRecord(name, QueryType.CNAME);
            List<string> result = new List<string>();
            if (null != data && data.Length > 0)
            {
                //we have a CNAME record
                foreach (var item in data)
                {
                    if (!(item is string))
                        continue;
                    var record = new DkimSource();
                    record.Source = (string)item;
                    var data2 = GetRecord(record.Source, QueryType.TXT);
                    record.Value.AddRange(data2.Select(x => (string)x));
                    retVal.Add(record);
                }
            }
            else
            {
                data = GetRecord(name, QueryType.TXT);
                foreach(var item in data)
                {
                    if (!(item is string))
                        continue;
                    var record = new DkimSource();
                    record.Source = name;
                    record.Value.Add((string)item);
                    retVal.Add(record);
                }
            }

            return retVal.ToArray();
        }

        public string[] GetDmarcRecord(string name)
        {
            var data = GetRecord(name, QueryType.TXT);
            List<string> result = new List<string>();
            if (null != data)
            {
                foreach (var item in data)
                {
                    if (!(item is string))
                        continue;
                    result.Add((string)item);

                }
            }
            return result.ToArray();
        }
    }
}
