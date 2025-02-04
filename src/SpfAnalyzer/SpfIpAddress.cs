using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;

namespace SpfAnalyzer
{
    public class SpfIpAddress
    {
        public string Source { get; set; }
        public IPAddress Address { get; set; }

        public SpfIpAddress(string source, IPAddress address)
        {
            Source = source;
            Address = address;
        }

        public SpfIpNetwork ToNetwork(int prefixLength)
        {
            return new SpfIpNetwork(Source, Address, prefixLength);
        }

        public static SpfIpAddress Parse(string source, string value)
        {
            if (IPAddress.TryParse(value, out var address))
            {
                return new SpfIpAddress(source, address);
            }
            throw new ArgumentException($"Invalid IP address: {value}");
        }
        public override string ToString()
        {
            return Address.ToString();
        }
    }
}
