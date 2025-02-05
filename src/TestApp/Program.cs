
namespace TestApp
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var domain = "ibm.com";
            var record = SpfAnalyzer.Dns.GetSpfRecord(domain);
            
            if(SpfAnalyzer.SpfRecord.TryParse(domain, domain, record[0], 0, null, out var results))
                foreach (var result in results)
                {
                    Console.WriteLine(result.ToString());
                }
        }
    }
}
