using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SpfAnalyzer
{
    public class DkimSource
    {
        //source record: either TXT or CNAME
        public string Source { get; set; }
        //value of the record
        public string[] Value { get; set; }
    }
}
