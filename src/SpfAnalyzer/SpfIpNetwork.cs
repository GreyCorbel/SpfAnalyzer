using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SpfAnalyzer
{
    public class SpfIpNetwork
    {
        private IPNetwork? _network = null;


        public string? Source { get; set; }
        public IPAddress? BaseAddress { 
            get
            {
                return _network?.BaseAddress;
            }
        }
        public int? PrefixLength
        {
            get
            {
                return _network?.PrefixLength;
            }
        }

        public SpfIpNetwork()
        {
        }

        public SpfIpNetwork(string source, IPNetwork network)
        {
            Source = source;
            _network = network;
        }
        public SpfIpNetwork(string source, IPAddress address, int prefixLength)
        {
            Source = source;
            _network = new IPNetwork(address, prefixLength);
        }
        public bool Contains(IPAddress address)
        {
            return _network?.Contains(address) ?? false;
        }
        public static bool TryParse(string source, string cidr, ILogger? logger, out SpfIpNetwork network)
        {
            var parts = cidr.Split('/');
            if (parts.Length != 2)
            {
                throw new ArgumentException($"Invalid CIDR format: {cidr}");
            }
            try
            {
                var address = IPAddress.Parse(parts[0]);
                var prefixLength = int.Parse(parts[1]);
                network = new SpfIpNetwork(source, address, prefixLength);
                return true;
            }
            catch (Exception)
            {
                logger?.LogWarning($"Invalid network address: {parts[0]}");
            }
            network = new SpfIpNetwork();
            return false;
        }
        public override string ToString()
        {
            return $"{BaseAddress}/{PrefixLength}";
        }
    }
}
