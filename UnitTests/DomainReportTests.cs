using System;
using System.Threading.Tasks;
using VirusTotalNET.Objects;
using Xunit;

namespace UnitTests
{
    public class DomainReportTests : TestBase
    {
        [Fact]
        public async Task GetDomainReportKnownDomain()
        {
            DomainReport report = await VirusTotal.GetDomainReport("google.com");
            Assert.Equal(ReportResponseCode.Present, report.ResponseCode);
        }

        [Fact]
        public async Task GetDomainReportUnknownDomain()
        {
            DomainReport report = await VirusTotal.GetDomainReport(Guid.NewGuid() + ".com");
            Assert.Equal(ReportResponseCode.NotPresent, report.ResponseCode);
        }
    }
}
