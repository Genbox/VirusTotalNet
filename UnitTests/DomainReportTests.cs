using System;
using System.Threading.Tasks;
using VirusTotalNET.ResponseCodes;
using VirusTotalNET.Results;
using VirusTotalNET.UnitTests.TestInternals;
using Xunit;

namespace VirusTotalNET.UnitTests
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
            IgnoreMissingJson(" / Alexa category", " / Alexa domain info", " / Alexa rank", " / BitDefender category", " / BitDefender domain info", " / Categories", " / detected_communicating_samples", " / detected_downloaded_samples", " / detected_referrer_samples", " / detected_urls", " / domain_siblings", " / Dr.Web category", " / Opera domain info", " / Pcaps", " / Resolutions", " / subdomains", " / TrendMicro category", " / undetected_communicating_samples", " / undetected_downloaded_samples", " / undetected_referrer_samples", " / Websense ThreatSeeker category", " / Webutation domain info", " / whois", " / whois_timestamp", " / WOT domain info");

            DomainReport report = await VirusTotal.GetDomainReport(Guid.NewGuid() + ".com");
            Assert.Equal(ReportResponseCode.NotPresent, report.ResponseCode);
        }
    }
}
