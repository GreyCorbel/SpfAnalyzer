using DnsClient;
using System.Net;

namespace SpfAnalyzer
{
    public class Dns
    {
        private readonly LookupClient _client;
        //this is underlying client defaults
        public TimeSpan Timeout { get; set; } = new TimeSpan(0, 0, 5);
        public int Retries { get; set; } = 2;

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
            var opts =  new DnsQueryAndServerOptions();
            opts.Timeout = Timeout;
            opts.Retries = Retries;

            var question = new DnsQuestion(name, queryType);

            switch (queryType)
            {
                case QueryType.A:
                case QueryType.AAAA:
                    var aRecords = _client.Query(question, opts).AllRecords.ARecords();
                    foreach (var record in aRecords)
                    {
                        result.Add(record.Address);
                    }
                    break;
                case QueryType.TXT:
                    var response = _client.Query(question, opts);
                    var txtRecords = response.AllRecords.TxtRecords();
                    foreach (var record in txtRecords)
                    {
                        //single TXT record can span multiple lines, so we need to join them
                        result.Add(string.Join(string.Empty,record.Text));
                    }
                    break;
                case QueryType.MX:
                    var mxRecords = _client.Query(question, opts).AllRecords.MxRecords();
                    foreach (var record in mxRecords)
                    {
                        result.Add(record.Exchange.Value);
                    }
                    break;
                case QueryType.CNAME:
                    var cnameRecords = _client.Query(question, opts).AllRecords.CnameRecords();
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
            return [.. result];
        }

        public DkimSource[] GetDkimRecord(string name)
        {
            var retVal = new List<DkimSource>();
            //try CNAME first to see if there's redirection
            var data = GetRecord(name, QueryType.CNAME);
            List<string> result = new List<string>();
            if (null != data && data.Length > 0)
            {
                //we have a CNAME record
                foreach (var item in data)
                {
                    if (!(item is string))
                        continue;
                    List<string> values = new List<string>();
                    var record = new DkimSource();
                    record.Source = (string)item;
                    var data2 = GetRecord(record.Source, QueryType.TXT);
                    values.AddRange(data2.Select(x => (string)x));
                    record.Value = [.. values];
                    retVal.Add(record);
                }
            }
            else
            {
                //no CNAME, try TXT directly
                data = GetRecord(name, QueryType.TXT);
                foreach(var item in data)
                {
                    if (!(item is string))
                        continue;
                    var record = new DkimSource();
                    List<string> values = new List<string>();

                    record.Source = name;
                    values.Add((string)item);
                    record.Value = [.. values];
                    retVal.Add(record);
                }
            }

            return [.. retVal];
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
            return [.. result];
        }
    }
}
