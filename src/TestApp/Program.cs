
namespace TestApp
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var domain = "ibm.com";
            var record = SpfAnalyzer.Dns.GetSpfRecord(domain);
            var results = SpfAnalyzer.SpfRecord.Parse(domain, domain, record[0], 0);
            foreach (var result in results)
            {
                Console.WriteLine(result.ToString());
            }
        }
    }
}
