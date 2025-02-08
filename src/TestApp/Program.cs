
namespace TestApp
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var domain = "deutschepost.de";
            var record = "dkim.sandboxdpdhl._domainkey";
            var fqdn = $"{record}.{domain}";
            var dns = new SpfAnalyzer.Dns(null);
            var dkim = dns.GetDkimRecord(fqdn);
            if (dkim.Length > 0)
            {

                if (SpfAnalyzer.DkimRecord.TryParse(domain, fqdn, dkim[0].Source, dkim[0].Value[0], null, out var results))
                    foreach (var result in results)
                    {
                        Console.WriteLine(result.ToString());
                    }
            }
        }
    }
}
