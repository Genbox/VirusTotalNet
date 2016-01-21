using System;
using System.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using VirusTotalNET;
using VirusTotalNET.Objects;

namespace UnitTests
{
    [TestClass]
    public class DomainReportTests
    {
        private static VirusTotal _virusTotal;

        [ClassInitialize]
        public static void Initialize(TestContext context)
        {
            _virusTotal = new VirusTotal(ConfigurationManager.AppSettings["ApiKey"]);
        }

        [TestMethod]
        public void GetDomainReportKnownDomain()
        {
            DomainReport report = _virusTotal.GetDomainReport("google.com");
            Assert.AreEqual(ReportResponseCode.Present, report.ResponseCode);
        }

        [TestMethod]
        public void GetDomainReportKnownDomain2()
        {
            DomainReport report = _virusTotal.GetDomainReport("fenggui.f3322.net");
            Assert.AreEqual(ReportResponseCode.Present, report.ResponseCode);

            Assert.AreEqual(99, report.Subdomains.Count);
            Assert.AreEqual(1, report.DetectedCommunicatingSamples.Count);
            Assert.AreEqual(1, report.DetectedUrls.Count);
        }

        [TestMethod]
        public void GetDomainReportUnknownDomain()
        {
            DomainReport report = _virusTotal.GetDomainReport(Guid.NewGuid() + ".com");
            Assert.AreEqual(ReportResponseCode.NotPresent, report.ResponseCode);
        }

        [TestMethod]
        public void GetDomainReportInvalidDomain()
        {
            DomainReport report = _virusTotal.GetDomainReport("asdfasdfas");
            Assert.AreEqual(ReportResponseCode.NotPresent, report.ResponseCode);
        }
    }
}
