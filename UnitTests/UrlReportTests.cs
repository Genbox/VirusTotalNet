using System;
using System.Collections.Generic;
using System.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using VirusTotalNET;
using VirusTotalNET.Objects;

namespace UnitTests
{
    [TestClass]
    public class UrlReportTests
    {
        private static VirusTotal _virusTotal;

        [ClassInitialize]
        public static void Initialize(TestContext context)
        {
            _virusTotal = new VirusTotal(ConfigurationManager.AppSettings["ApiKey"]);

            // Copyright Keith J. Jones © 2016
            _virusTotal.IsPrivateKey = true;
        }

        [TestMethod]
        public void GetReportKnownUrl()
        {
            UrlReport urlReport = _virusTotal.GetUrlReport("google.com");
            Assert.AreEqual(ReportResponseCode.Present, urlReport.ResponseCode);
        }

        [TestMethod]
        public void GetMultipleReportKnownUrl()
        {
            string[] urls = { "google.se", "http://google.com", "https://virustotal.com" };

            List<UrlReport> urlReports = _virusTotal.GetUrlReports(urls);

            foreach (UrlReport urlReport in urlReports)
            {
                Assert.AreEqual(ReportResponseCode.Present, urlReport.ResponseCode);
            }
        }

        [TestMethod]
        public void GetReportUnknownUrl()
        {
            UrlReport urlReport = _virusTotal.GetUrlReport("VirusTotal.NET" + Guid.NewGuid() + ".com");
            Assert.AreEqual(ReportResponseCode.NotPresent, urlReport.ResponseCode);

            //We are not supposed to have a scan id
            Assert.IsTrue(string.IsNullOrWhiteSpace(urlReport.ScanId));
        }

        [TestMethod]
        public void GetMultipleReportUnknownUrl()
        {
            string[] urls = { "VirusTotal.NET" + Guid.NewGuid() + ".com", "VirusTotal.NET" + Guid.NewGuid() + ".com", "VirusTotal.NET" + Guid.NewGuid() + ".com" };

            List<UrlReport> urlReports = _virusTotal.GetUrlReports(urls);

            foreach (UrlReport urlReport in urlReports)
            {
                Assert.AreEqual(ReportResponseCode.NotPresent, urlReport.ResponseCode);
            }
        }

        [TestMethod]
        public void GetReportForUnknownUrlAndScan()
        {
            UrlReport urlReport = _virusTotal.GetUrlReport("VirusTotal.NET" + Guid.NewGuid() + ".com", true);

            //It return "present" because we told it to scan it
            Assert.AreEqual(ReportResponseCode.Present, urlReport.ResponseCode);

            //We are supposed to have a scan id because we scanned it
            Assert.IsFalse(string.IsNullOrWhiteSpace(urlReport.ScanId));
        }

        [TestMethod]
        [ExpectedException(typeof(Exception))]
        public void GetReportInvalidUrl()
        {
            UrlReport urlReport = _virusTotal.GetUrlReport(".");
        }
    }
}
