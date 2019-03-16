using System.Linq;
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
            DomainReport report = await VirusTotal.GetDomainReportAsync(TestData.KnownDomains.First());
            Assert.Equal(DomainResponseCode.Present, report.ResponseCode);
        }

        //[Fact]
        //public async Task GetDomainReportInvalidDomain()
        //{
        //    //TODO: I can't find a domain that VT does not think is valid.
        //    //Domains tried:
        //    //-
        //    //.
        //    //%20
        //    //%2F
        //}

        [Fact]
        public async Task GetDomainReportUnknownDomain()
        {
            //Reports don't contain all these fields when it is unknown
            IgnoreMissingJson(" / undetected_urls", " / Alexa category", " / Alexa domain info", " / Alexa rank", " / BitDefender category", " / BitDefender domain info", " / Categories", " / detected_communicating_samples", " / detected_downloaded_samples", " / detected_referrer_samples", " / detected_urls", " / domain_siblings", " / Dr.Web category", " / Forcepoint ThreatSeeker category", " / Opera domain info", " / Pcaps", " / Resolutions", " / subdomains", " / TrendMicro category", " / undetected_communicating_samples", " / undetected_downloaded_samples", " / undetected_referrer_samples", " / Websense ThreatSeeker category", " / Webutation domain info", " / whois", " / whois_timestamp", " / WOT domain info");

            DomainReport report = await VirusTotal.GetDomainReportAsync(TestData.GetUnknownDomains(1).First());
            Assert.Equal(DomainResponseCode.NotPresent, report.ResponseCode);
        }
    }
}