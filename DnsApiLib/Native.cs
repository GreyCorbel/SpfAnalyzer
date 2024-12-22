using System.Runtime.InteropServices;

namespace DnsApi
{
    class Native
    {
        #region Enums
        public enum DnsError
        {
            InvalidName = 123,
            InvalidFormat = 9001,
            ServerFailure = 9002,
            NameNotFound = 9003,
            RequestNotSupported = 9004,
            OperationRefused = 9005,
            UnexpectedName = 9006,
            NoRecordsFound = 9501
        }

        #endregion

        #region Structs
        public enum DNS_FREE_TYPE
        {
            DnsFreeFlat = 0,
            DnsFreeRecordList = 1,
            DnsFreeParsedMessageFields = 2,
        }

        [Flags]
        public enum QueryOptions
        {
            DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE = 1,
            DNS_QUERY_BYPASS_CACHE = 8,
            DNS_QUERY_DONT_RESET_TTL_VALUES = 0x100000,
            DNS_QUERY_NO_HOSTS_FILE = 0x40,
            DNS_QUERY_NO_LOCAL_NAME = 0x20,
            DNS_QUERY_NO_NETBT = 0x80,
            DNS_QUERY_NO_RECURSION = 4,
            DNS_QUERY_NO_WIRE_QUERY = 0x10,
            DNS_QUERY_RESERVED = -16777216,
            DNS_QUERY_RETURN_MESSAGE = 0x200,
            DNS_QUERY_STANDARD = 0,
            DNS_QUERY_TREAT_AS_FQDN = 0x1000,
            DNS_QUERY_USE_TCP_ONLY = 2,
            DNS_QUERY_WIRE_ONLY = 0x100
        }

        public enum QueryTypes
        {
            DNS_TYPE_A = 0x0001,
            DNS_TYPE_NS = 0x0002,
            DNS_TYPE_CNAME = 0x0005,
            DNS_TYPE_SOA = 0x0006,
            DNS_TYPE_MX = 0x000f,
            DNS_TYPE_SRV = 0x0021,
            DNS_TYPE_TEXT = 0x0010
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DNSRecordHeader
        {
            public IntPtr pNext;
            public IntPtr pName;
            public ushort wType;
            public ushort wDataLength;
            public int flags;
            public uint dwTtl;
            public int dwReserved;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DNS_PTR_DATA
        {
            public string pNameHost;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DNS_A_DATA
        {
            public UInt32 ipAddressData;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct PtrRecord
        {
            public DNSRecordHeader hdr;
            public DNS_PTR_DATA data;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ARecord
        {
            public DNSRecordHeader hdr;
            public DNS_A_DATA data;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DNS_SOA_DATA
        {
            public string pNamePrimaryServer;
            public string pNameAdministrator;
            public UInt32 dwSerialNo;
            public UInt32 dwRefresh;
            public UInt32 dwRetry;
            public UInt32 dwExpire;
            public UInt32 dwDefaultTtl;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SoaRecord
        {
            public DNSRecordHeader hdr;
            public DNS_SOA_DATA data;
        }


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DNS_TXT_DATA
        {
            public UInt32 dwStringCount;
            [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.LPTStr, SizeConst = 3)]
            public string[] data;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TxtRecord
        {
            public DNSRecordHeader hdr;
            public DNS_TXT_DATA data;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DNS_SRV_DATA
        {
            public IntPtr pNameTarget;
            public ushort wPriority;
            public ushort wWeight;
            public ushort wPort;
            public short Pad;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SRVRecord
        {
            public DNSRecordHeader hdr;
            public DNS_SRV_DATA srv;
        }
        #endregion
        #region NativeMethods
        [DllImport("dnsapi", EntryPoint = "DnsQuery_W", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        public static extern int DnsQuery(string name, QueryTypes recordType, QueryOptions options, [In, Out, Optional] IntPtr pExtra, ref IntPtr ppQueryResults, IntPtr pReserved = default);

        [DllImport("dnsapi", EntryPoint = "DnsFree", CharSet = CharSet.Unicode, SetLastError = false, ExactSpelling = true)]
        public static extern void DnsFree(IntPtr data, DNS_FREE_TYPE type);
        #endregion
    }
}
