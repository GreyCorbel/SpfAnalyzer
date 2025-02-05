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

        public SpfIpAddress()
        {
            Source = string.Empty;
            Address = IPAddress.None;
        }
        public SpfIpAddress(string source, IPAddress address)
        {
            Source = source;
            Address = address;
        }

        public SpfIpNetwork ToNetwork(int prefixLength)
        {
            return new SpfIpNetwork(Source, Address, prefixLength);
        }

        public static bool TryParse(string source, string value, ILogger? logger, out SpfIpAddress spfAddress)
        {
            if (IPAddress.TryParse(value, out var address))
            {
                spfAddress = new SpfIpAddress(source, address);
                return true;
            }
            logger?.LogWarning($"Invalid IP address: {value}");
            spfAddress = new SpfIpAddress();
            return false;
        }
        public override string ToString()
        {
            return Address.ToString();
        }
    }
}
