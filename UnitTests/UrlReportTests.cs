using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using VirusTotalNET.Objects;
using Xunit;

namespace UnitTests
{
    public class UrlReportTests : TestBase
    {
        [Fact]
        public async Task GetReportKnownUrl()
        {
            UrlReport urlReport = await VirusTotal.GetUrlReport("google.com");
            Assert.Equal(ReportResponseCode.Present, urlReport.ResponseCode);
        }

        [Fact]
        public async Task GetMultipleReportKnownUrl()
        {
            string[] urls = { "google.se", "http://google.com", "https://virustotal.com" };

            List<UrlReport> urlReports = await VirusTotal.GetUrlReports(urls);

            foreach (UrlReport urlReport in urlReports)
            {
                Assert.Equal(ReportResponseCode.Present, urlReport.ResponseCode);
            }
        }

        [Fact]
        public async Task GetReportUnknownUrl()
        {
            UrlReport urlReport = await VirusTotal.GetUrlReport("VirusTotal.NET" + Guid.NewGuid() + ".com");
            Assert.Equal(ReportResponseCode.NotPresent, urlReport.ResponseCode);

            //We are not supposed to have a scan id
            Assert.True(string.IsNullOrWhiteSpace(urlReport.ScanId));
        }

        [Fact]
        public async Task GetMultipleReportUnknownUrl()
        {
            string[] urls = { "VirusTotal.NET" + Guid.NewGuid() + ".com", "VirusTotal.NET" + Guid.NewGuid() + ".com", "VirusTotal.NET" + Guid.NewGuid() + ".com" };

            List<UrlReport> urlReports = await VirusTotal.GetUrlReports(urls);

            foreach (UrlReport urlReport in urlReports)
            {
                Assert.Equal(ReportResponseCode.NotPresent, urlReport.ResponseCode);
            }
        }

        [Fact]
        public async Task GetReportForUnknownUrlAndScan()
        {
            UrlReport urlReport = await VirusTotal.GetUrlReport("VirusTotal.NET" + Guid.NewGuid() + ".com", true);

            //It return "present" because we told it to scan it
            Assert.Equal(ReportResponseCode.Present, urlReport.ResponseCode);

            //We are supposed to have a scan id because we scanned it
            Assert.False(string.IsNullOrWhiteSpace(urlReport.ScanId));
        }

        [Fact]
        public async Task GetReportInvalidUrl()
        {
            await Assert.ThrowsAsync<Exception>(async () => await VirusTotal.GetUrlReport("."));
        }
    }
}
