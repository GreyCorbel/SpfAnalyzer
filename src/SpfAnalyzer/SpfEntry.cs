using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SpfAnalyzer
{
    public class SpfEntry
    {
        public string? Domain { get; set; }
        public string? Source { get; set; }
        public string? Prefix { get; set; }
        public string? Value { get; set; }

        public SpfEntry()
        {
        }
        public SpfEntry(string domain, string source, string prefix, string value)
        {
            Domain = domain;
            Source = source;
            Prefix = prefix;
            Value = value;
        }
        public override string ToString()
        {
            return $"{Prefix} {Value}";
        }
    }
}
