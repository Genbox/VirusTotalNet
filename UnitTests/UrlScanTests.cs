using System;
using System.Collections.Generic;
using System.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using VirusTotalNET;
using VirusTotalNET.Objects;

namespace UnitTests
{
    [TestClass]
    public class UrlScanTests
    {
        private static VirusTotal _virusTotal;

        [ClassInitialize]
        public static void Initialize(TestContext context)
        {
            _virusTotal = new VirusTotal(ConfigurationManager.AppSettings["ApiKey"]);
        }

        [TestMethod]
        public void ScanKnownUrl()
        {
            ScanResult fileResult = _virusTotal.ScanUrl("google.com");
            Assert.AreEqual(ScanResponseCode.Queued, fileResult.ResponseCode);
        }

        [TestMethod]
        public void ScanMultipleKnownUrls()
        {
            string[] urls = { "google.se", "http://google.com", "https://virustotal.com" };

            List<ScanResult> urlScans = _virusTotal.ScanUrls(urls);

            foreach (ScanResult urlScan in urlScans)
            {
                Assert.AreEqual(ScanResponseCode.Queued, urlScan.ResponseCode);
            }
        }

        [TestMethod]
        public void ScanUnknownUrl()
        {
            ScanResult fileResult = _virusTotal.ScanUrl("VirusTotal.NET" + Guid.NewGuid() + ".com");
            Assert.AreEqual(ScanResponseCode.Queued, fileResult.ResponseCode);
        }

        [TestMethod]
        public void ScanMultipleUnknownUrl()
        {
            string[] urls = { "VirusTotal.NET" + Guid.NewGuid() + ".com", "VirusTotal.NET" + Guid.NewGuid() + ".com", "VirusTotal.NET" + Guid.NewGuid() + ".com", "VirusTotal.NET" + Guid.NewGuid() + ".com" };

            List<ScanResult> urlScans = _virusTotal.ScanUrls(urls);

            foreach (ScanResult urlScan in urlScans)
            {
                Assert.AreEqual(ScanResponseCode.Queued, urlScan.ResponseCode);
            }
        }
    }
}
