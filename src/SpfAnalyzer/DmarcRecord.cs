using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SpfAnalyzer
{
    public class DmarcRecord
    {
        string? _rawRecord;

        public string? Domain { get; set; }
        public string Version { get; set; } = "DMARC1";
        public string? Source { get; set; }

        List<DmarcEntry> _entries = new List<DmarcEntry>();
        public IReadOnlyList<DmarcEntry> Entries => _entries;

        public DmarcRecord()
        {
        }

        public DmarcRecord(string domain, string source, string rawRecord)
        {
            Domain = domain;
            Source = source;
            _rawRecord = rawRecord;
        }

        public static bool TryParse(string domain, string source, string rawRecord, ILogger? logger, out DmarcRecord[] dmarcRecord)
        {
            logger?.LogVerbose($"Processing record {rawRecord}");
            var retVal = new List<DmarcRecord>();

            var record = new DmarcRecord(domain, source, rawRecord);
            retVal.Add(record);

            var parts = rawRecord.Split(';');

            foreach(var part in parts)
            {
                var token = part.Trim();
                if (string.IsNullOrEmpty(token))
                {
                    continue;
                }
                var idx = token.IndexOf('=');
                var tag = token.Substring(0, idx);
                var value = token.Substring(idx + 1);
                if (tag == "v")
                {
                    record.Version = value;
                }
                else
                {
                    record._entries.Add(new DmarcEntry(domain, source, tag, value));
                }
            }
            dmarcRecord = retVal.ToArray();
            return true;
        }

        public override string ToString()
        {
            return _rawRecord?? string.Empty;
        }
    }
}
