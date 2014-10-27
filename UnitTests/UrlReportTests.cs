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
        }

        [TestMethod]
        public void GetReportKnownUrl()
        {
            Report report = _virusTotal.GetUrlReport("google.com");
            Assert.AreEqual(ReportResponseCode.Present, report.ResponseCode);
        }

        [TestMethod]
        public void GetMultipleReportKnownUrl()
        {
            string[] urls = { "google.se", "http://google.com", "https://virustotal.com" };

            List<Report> reports = _virusTotal.GetUrlReports(urls);

            foreach (Report report in reports)
            {
                Assert.AreEqual(ReportResponseCode.Present, report.ResponseCode);
            }
        }

        [TestMethod]
        public void GetReportUnknownUrl()
        {
            Report report = _virusTotal.GetUrlReport("VirusTotal.NET" + Guid.NewGuid() + ".com");
            Assert.AreEqual(ReportResponseCode.NotPresent, report.ResponseCode);

            //We are not supposed to have a scan id
            Assert.IsTrue(string.IsNullOrWhiteSpace(report.ScanId));
        }

        [TestMethod]
        public void GetMultipleReportUnknownUrl()
        {
            string[] urls = { "VirusTotal.NET" + Guid.NewGuid() + ".com", "VirusTotal.NET" + Guid.NewGuid() + ".com", "VirusTotal.NET" + Guid.NewGuid() + ".com" };

            List<Report> reports = _virusTotal.GetUrlReports(urls);

            foreach (Report report in reports)
            {
                Assert.AreEqual(ReportResponseCode.NotPresent, report.ResponseCode);
            }
        }

        [TestMethod]
        public void GetReportForUnknownUrlAndScan()
        {
            Report report = _virusTotal.GetUrlReport("VirusTotal.NET" + Guid.NewGuid() + ".com", true);

            //It return "present" because we told it to scan it
            Assert.AreEqual(ReportResponseCode.Present, report.ResponseCode);

            //We are supposed to have a scan id because we scanned it
            Assert.IsFalse(string.IsNullOrWhiteSpace(report.ScanId));
        }

        [TestMethod]
        [ExpectedException(typeof(Exception))]
        public void GetReportInvalidUrl()
        {
            Report report = _virusTotal.GetUrlReport(".");
        }
    }
}
