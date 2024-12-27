
using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace DnsApi
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
        private readonly string _rawRecord;
        public string? Version { get; set; }
        public SpfAction FinalAction { get; set; }
        public string? Source { get; set; }
        public List<object> Entries { get; set; }

        public SpfRecord(string source, string rawRecord)
        {
            _rawRecord = rawRecord;
            Source = source;
            FinalAction = SpfAction.Neutral;
            Entries = new List<object>();
        }

        public override string ToString()
        {
            return $"Source: {Source} Record: {_rawRecord}";
        }
    }
    public abstract class SpfEntryBase
    {
        public string? Value { get; set; }

        public override string? ToString()
        {
            return Value;
        }
    }

    public class SpfEntryInclude : SpfEntryBase 
    {
        public override string? ToString()
        {
            return $"include {Value}";
        }
    }

    public class SpfEntryRedirect : SpfEntryBase
    {
        public override string? ToString()
        {
            return $"redirect {Value}";
        }
    }


    public class SpfEntryExplain : SpfEntryBase
    {
        public override string? ToString()
        {
            return $"exp {Value}";
        }
    }

    public class SpfEntryInvalidNetwork : SpfEntryBase
    {
        public override string? ToString()
        {
            return $"InvalidNetwork {Value}";
        }
    }

    public class SpfEntryInvalidAddress : SpfEntryBase
    {
        public override string? ToString()
        {
            return $"InvalidAddress {Value}";
        }
    }

    public class SpfEntryOther:SpfEntryBase
    {
        public string? Prefix { get; set; }

        public override string? ToString()
        {
            return $"{Prefix} {Value}";
        }
    }

    public class SpfIpNetwork:IEquatable<SpfIpNetwork>
    {
        private readonly IPNetwork _ipNetwork;

        public string Source { get; set; }

        public IPAddress BaseAddress => _ipNetwork.BaseAddress;
        public int PrefixLength => _ipNetwork.PrefixLength;

        public SpfIpNetwork(string source, IPNetwork network)
        {
            _ipNetwork = network;
            Source = source;
        }
        public SpfIpNetwork(string source, IPAddress ip, int prefixLength)
        {
            try
            {
                _ipNetwork = new IPNetwork(ip, prefixLength);

            }
            catch(ArgumentException ex)
            {
                // ip address has bits after mask => we need to mask it ourselves
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    uint mask = uint.MaxValue << (32 - prefixLength);
                    if (BitConverter.IsLittleEndian)
                    {
                        mask = BinaryPrimitives.ReverseEndianness(mask);
                    }
                    uint addr = BitConverter.ToUInt32(ip.GetAddressBytes());
                    addr &= mask;
                    _ipNetwork = new IPNetwork(new IPAddress(addr), prefixLength);
                }
                else
                {
                    UInt128 addressValue = default;
                    ip.TryWriteBytes(MemoryMarshal.AsBytes(new Span<UInt128>(ref addressValue)), out int bytesWritten);

                    UInt128 mask = UInt128.MaxValue << (128 - prefixLength);
                    if (BitConverter.IsLittleEndian)
                    {
                        mask = BinaryPrimitives.ReverseEndianness(mask);
                    }

                    UInt128 addr = addressValue & mask;
                    var buff = MemoryMarshal.AsBytes(new Span<UInt128>(ref addr));
                    _ipNetwork = new IPNetwork(new IPAddress(buff), prefixLength);
                }
            }
            Source = source;
        }

        public override string ToString()
        {
            return _ipNetwork.ToString();
        }

        public bool Equals(SpfIpNetwork? other)
        {
            return other != null && BaseAddress == other.BaseAddress && PrefixLength == other.PrefixLength;
        }

        public override bool Equals(object? obj)
        {
            return obj is SpfIpNetwork other && Equals(other);
        }

        public override int GetHashCode()
        {
            return _ipNetwork.GetHashCode();
        }
    }
    
    public class SpfIpAddress : IPAddress
    {
        /// <summary>
        /// From which SPF record the address was parsed
        /// </summary>
        public string? Source { get; set; }

        public SpfIpAddress(string source, IPAddress address) : base(address.GetAddressBytes())
        {
            Source = source;
        }
        public SpfIpAddress(byte[] address) : base(address)
        {
        }

        public SpfIpAddress(long newAddress) : base(newAddress)
        {
        }

        public SpfIpAddress(byte[] address, long scopeid) : base(address, scopeid)
        {
        }

        public SpfIpAddress(ReadOnlySpan<byte> newAddress, long scopeid) : base(newAddress, scopeid)
        {
        }

        public static bool TryParse(string source, string ip, out SpfIpAddress? result)
        {
            if (System.Net.IPAddress.TryParse(ip, out var address))
            {
                result = new SpfIpAddress(address.GetAddressBytes());
                result.Source = source;
                return true;
            }
            result = null;
            return false;
        }
        public override string ToString()
        {
            return base.ToString();
        }
    }
}
