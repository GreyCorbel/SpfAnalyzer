using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace SpfIpHelper
{
    public static class IPAddressExtensions
    {
        /// <summary>
        /// Creates IPNetwork from IP address and given prefix length
        /// </summary>
        /// <param name="address">IP address to mask (ipv4 or ipv6)</param>
        /// <param name="prefixLength">Number of bits to mask</param>
        /// <param name="force">Creates IPNetwork even when IP address is not on low boundary of resulting network</param>
        /// <returns></returns>
        public static IPNetwork Mask(this IPAddress address, int prefixLength, bool force=false)
        {
            try
            {
                return new IPNetwork(address, prefixLength);
            }
            catch (ArgumentException)
            {
                if (!force)
                    throw;
                // ip address has bits after mask => we need to mask it ourselves
                if (address.AddressFamily == AddressFamily.InterNetwork)
                {
                    uint mask = uint.MaxValue << (32 - prefixLength);
                    if (BitConverter.IsLittleEndian)
                    {
                        mask = BinaryPrimitives.ReverseEndianness(mask);
                    }
                    uint addr = BitConverter.ToUInt32(address.GetAddressBytes());
                    addr &= mask;
                    return new IPNetwork(new IPAddress(addr), prefixLength);
                }
                else
                {
                    UInt128 addressValue = default;
                    address.TryWriteBytes(MemoryMarshal.AsBytes(new Span<UInt128>(ref addressValue)), out int bytesWritten);

                    UInt128 mask = UInt128.MaxValue << (128 - prefixLength);
                    if (BitConverter.IsLittleEndian)
                    {
                        mask = BinaryPrimitives.ReverseEndianness(mask);
                    }

                    UInt128 addr = addressValue & mask;
                    var buff = MemoryMarshal.AsBytes(new Span<UInt128>(ref addr));
                    return new IPNetwork(new IPAddress(buff), prefixLength);
                }
            }
        }

        public static string ToDotted(this IPAddress address)
        {
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                return address.ToString();
            }
            else
            {
                string plain = GetIpv6Plain(address);
                var sb = new StringBuilder();
                foreach (var c in plain)
                {
                    sb.Append(c);
                    sb.Append('.');
                }
                return sb.ToString().Substring(0, sb.Length - 1);
            }
        }
        public static string ToReverseDotted(this IPAddress address)
        {
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                return string.Join('.', address.ToString().Split('.').Reverse());
            }
            else
            {
                string plain = GetIpv6Plain(address);
                var sb = new StringBuilder();
                for (int i = (plain.Length) - 1; i >= 0; i--)
                {
                    sb.Append(plain[i]);
                    sb.Append('.');
                }
                return sb.ToString().Substring(0, sb.Length - 1);
            }
        }

        private static string GetIpv6Plain(this IPAddress address)
        {
            UInt128 addressValue = default;
            address.TryWriteBytes(MemoryMarshal.AsBytes(new Span<UInt128>(ref addressValue)), out int bytesWritten);
            return BitConverter.ToString(MemoryMarshal.AsBytes(new Span<UInt128>(ref addressValue)).ToArray()).Replace("-", "");
        }

    }
}
