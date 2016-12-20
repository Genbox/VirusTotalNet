using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using UnitTests.TestInternals;
using VirusTotalNET.ResponseCodes;
using VirusTotalNET.Results;
using Xunit;

namespace UnitTests
{
    public class UrlScanTests : TestBase
    {
        [Fact]
        public async Task ScanKnownUrl()
        {
            UrlScanResult fileResult = await VirusTotal.ScanUrl("google.com");
            Assert.Equal(ScanResponseCode.Queued, fileResult.ResponseCode);
        }

        [Fact]
        public async Task ScanMultipleKnownUrls()
        {
            string[] urls = { "google.se", "http://google.com", "https://virustotal.com" };

            List<UrlScanResult> urlScans = await VirusTotal.ScanUrls(urls);

            foreach (UrlScanResult urlScan in urlScans)
            {
                Assert.Equal(ScanResponseCode.Queued, urlScan.ResponseCode);
            }
        }

        [Fact]
        public async Task ScanUnknownUrl()
        {
            UrlScanResult fileResult = await VirusTotal.ScanUrl("VirusTotal.NET" + Guid.NewGuid() + ".com");
            Assert.Equal(ScanResponseCode.Queued, fileResult.ResponseCode);
        }

        [Fact]
        public async Task ScanMultipleUnknownUrl()
        {
            string[] urls = { "VirusTotal.NET" + Guid.NewGuid() + ".com", "VirusTotal.NET" + Guid.NewGuid() + ".com", "VirusTotal.NET" + Guid.NewGuid() + ".com", "VirusTotal.NET" + Guid.NewGuid() + ".com", "VirusTotal.NET" + Guid.NewGuid() + ".com" };

            List<UrlScanResult> urlScans = await VirusTotal.ScanUrls(urls);

            foreach (UrlScanResult urlScan in urlScans)
            {
                Assert.Equal(ScanResponseCode.Queued, urlScan.ResponseCode);
            }
        }
    }
}
