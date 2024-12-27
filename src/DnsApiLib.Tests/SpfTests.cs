using Microsoft.VisualStudio.TestTools.UnitTesting;
using DnsApi;
namespace DnsApiLib.Tests
{
    [TestClass]
    public sealed class SpfTests
    {
        [TestMethod("Test basic record parsing")]
        public void TestVersionAndAction()
        {
            var rawRecord = "v=spf1 -all";
            var domain = "greycorbel.com";
            var result = Domain.ParseSpfRecord(domain, rawRecord);
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Count == 1);
            var rslt = result[0];
            Assert.AreEqual($"Source: {domain} Record: {rawRecord}", rslt.ToString());
            Assert.AreEqual("greycorbel.com", rslt.Source);
            Assert.AreEqual(SpfAction.Fail, rslt.FinalAction);
            Assert.AreEqual(rslt.Entries.Count, 0);
        }

        [TestMethod("Test ALL is terminating")]
        public void TestTerminatingAll()
        {
            var rawRecord = "v=spf1 -all ptr";
            var domain = "greycorbel.com";
            var result = Domain.ParseSpfRecord(domain, rawRecord);
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Count == 1);
            var rslt = result[0];
            Assert.AreEqual(rslt.Entries.Where(x => x is SpfEntryOther && ((SpfEntryOther)x).Prefix == "ptr").Count(), 0);
            Assert.AreEqual($"Source: {domain} Record: {rawRecord}", rslt.ToString());
            Assert.AreEqual("greycorbel.com", rslt.Source);
            Assert.AreEqual(SpfAction.Fail, rslt.FinalAction);
        }

        [TestMethod("Test PTR record parsing")]
        public void TestPtr()
        {
            var rawRecord = "v=spf1 ptr -all";
            var domain = "greycorbel.com";
            var result = Domain.ParseSpfRecord(domain, rawRecord);
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Count == 1);
            var rslt = result[0];
            Assert.AreEqual(rslt.Entries.Where(x => x is SpfEntryOther && ((SpfEntryOther)x).Prefix == "ptr").Count(), 1);
            Assert.AreEqual($"Source: {domain} Record: {rawRecord}", rslt.ToString());
            Assert.AreEqual("greycorbel.com", rslt.Source);
            Assert.AreEqual(SpfAction.Fail, rslt.FinalAction);
        }


        [TestMethod("Test MX mechanism")]
        [DataRow("mx", "greycorbel.com")]
        [DataRow("mx:greycorbel.com", "greycorbel.com")]
        [DataRow("mx:greycorbel.com/24", "greycorbel.com")]
        [DataRow("mx/24", "greycorbel.com")]
        public void TestMx(string data, string domain)
        {
            var rawRecord = $"v=spf1 {data} -all";
            var result = Domain.ParseSpfRecord(domain, rawRecord);
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Count == 1);
            var rslt = result[0];
            Assert.AreEqual($"Source: {domain} Record: {rawRecord}", rslt.ToString());

            Assert.AreEqual(rslt.Entries.Where(x=>x is SpfEntryOther && ((SpfEntryOther)x).Prefix == "mx").Count(), 1);

        }

        [TestMethod("Test A mechanism")]
        [DataRow("a", "microsoft.com")]
        [DataRow("a:microsoft.com", "microsoft.com")]
        [DataRow("a:microsoft.com/24", "microsoft.com")]
        [DataRow("a/24", "microsoft.com")]
        public void TestA(string data, string domain)
        {
            var rawRecord = $"v=spf1 {data} -all";
            var result = Domain.ParseSpfRecord(domain, rawRecord);
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Count == 1);
            var rslt = result[0];
            Assert.AreEqual($"Source: {domain} Record: {rawRecord}", rslt.ToString());

            Assert.AreEqual(rslt.Entries.Where(x => x is SpfEntryOther && ((SpfEntryOther)x).Prefix == "a").Count(), 1);

        }
    }
}
