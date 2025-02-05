using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SpfAnalyzer
{
    public class DkimRecord
    {
        static string[] _tags = ["v=", "h=", "k=", "n=", "p=", "s=", "t=", "o="];
        string? _rawRecord;
        public string? Domain { get; set; }
        public string Version { get; set; } = "DKIM1";
        public string? Source { get; set; }
        public DkimPublicKey? PublicKey { get; set; }

        List<DkimEntry> _entries = new List<DkimEntry>();
        public IReadOnlyList<DkimEntry> Entries => _entries;

        public DkimRecord()
        {
        }

        public DkimRecord(string domain, string source, string rawRecord)
        {
            Domain = domain;
            Source = source;
            _rawRecord = rawRecord;
        }

        public static bool TryParse(string domain, string source, string rawRecord, ILogger? logger, out DkimRecord[] dkimRecords)
        {
            logger?.LogVerbose($"Processing record {rawRecord}");
            var retVal = new List<DkimRecord>();
            var record = new DkimRecord(domain, source, rawRecord);
            retVal.Add(record);

            var parts = rawRecord.Split(';');
            var algo = "rsa";
            var key = string.Empty;

            foreach(var part in parts)
            {
                var token = part.Trim();
                if (string.IsNullOrEmpty(token))
                {
                    continue;
                }
                var tag = token.Substring(0, 2);
                if(tag == "v=")
                {
                    //split is there because some DKIM entries are filled in by SPF data
                    record.Version = token.Substring(2).Split(' ')[0];
                }
                else if (_tags.Contains(tag))
                {
                    record._entries.Add(new DkimEntry(domain,source,token.Substring(0,1), token.Substring(2)));
                    if(tag == "k=")
                    {
                        algo = token.Substring(2);
                    }
                    else if (tag == "p=")
                    {
                        key = token.Substring(2);
                    }
                }
                else
                {
                    //possible public key without tag -  e.g. salesforce20161220._domainkey.dhl.com.
                    record._entries.Add(new DkimEntry(domain, source, "p?", token));
                }

            }
            if(!string.IsNullOrEmpty(key))
            {
                record.PublicKey = DkimPublicKey.Parse(algo, key);
            }
            dkimRecords = [.. retVal];
            return true;
        }

        public override string ToString()
        {
            return _rawRecord ?? string.Empty;
        }
    }
}
