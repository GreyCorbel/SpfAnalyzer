using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DnsApi
{
    public class SpfRecord
    {
        private readonly string _rawRecord;
        public string? Version { get; set; }
        public string? Disposition { get; set; }
        public string? Source { get; set; }
        public List<object> Entries { get; set; }

        public SpfRecord(string source, string rawRecord)
        {
            _rawRecord = rawRecord;
            Source = source;
            Entries = new List<object>();
        }

        public override string ToString()
        {
            return $"Source: {Source} Record: {_rawRecord}";
        }
    }
    public class SpfEntryBase
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
}
