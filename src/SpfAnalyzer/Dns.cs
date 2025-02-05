using DnsClient;
using System.Net;

namespace SpfAnalyzer
{
    public static class Dns
    {
        static LookupClient _client;

        public static object[] GetRecord(string name, QueryType queryType, string? serverIpAddress=null)
        {
            if (string.IsNullOrEmpty(serverIpAddress))
                _client = new LookupClient();
            else
            {
                if(IPAddress.TryParse(serverIpAddress, out var ip))
                {
                    _client = new LookupClient(new LookupClientOptions(ip));
                }
                else
                {
                    throw new ArgumentException("Invalid IP address", nameof(serverIpAddress));
                }
            }
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

                    var txtRecords = _client.Query(name, queryType).AllRecords.TxtRecords();
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

            }
            return [.. result];
        }

        public static string[] GetSpfRecord(string name, string? serverIpAddress = null)
        {
            var data = GetRecord(name, QueryType.TXT, serverIpAddress);
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

        public static string[] GetDkimRecord(string name, string? serverIpAddress = null)
        {
            var data = GetRecord(name, QueryType.TXT, serverIpAddress);
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

        public static string[] GetDmarcRecord(string name, string? serverIpAddress = null)
        {
            var data = GetRecord(name, QueryType.TXT, serverIpAddress);
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
