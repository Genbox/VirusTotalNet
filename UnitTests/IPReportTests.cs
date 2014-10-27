using System.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using VirusTotalNET;
using VirusTotalNET.Objects;

namespace UnitTests
{
    [TestClass]
    public class IPReportTests
    {
        private static VirusTotal _virusTotal;

        [ClassInitialize]
        public static void Initialize(TestContext context)
        {
            _virusTotal = new VirusTotal(ConfigurationManager.AppSettings["ApiKey"]);
        }

        [TestMethod]
        public void GetIPReportKnownIP()
        {
            IPReport report = _virusTotal.GetIPReport("184.105.139.067"); //google.com
            Assert.AreEqual(ReportResponseCode.Present, report.ResponseCode);
        }
    }
}
