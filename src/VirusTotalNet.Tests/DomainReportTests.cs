using System.Linq;
using System.Threading.Tasks;
using VirusTotalNet.ResponseCodes;
using VirusTotalNet.Results;
using VirusTotalNet.Tests.TestInternals;
using Xunit;

namespace VirusTotalNet.Tests;

public class DomainReportTests : TestBase
{
    [Fact]
    public async Task GetDomainReportKnownDomain()
    {
        IgnoreMissingJson(" / Alexa category", " / alphaMountain.ai category", " / Categories", " / Comodo Valkyrie Verdict category", " / Dr.Web category", " / TrendMicro category", " / Websense ThreatSeeker category");

        DomainReport report = await VirusTotal.GetDomainReportAsync(TestData.KnownDomains[0]);
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
        IgnoreMissingJson(" / Alexa category", " / Alexa domain info", " / Alexa rank", " / alphaMountain.ai category", " / BitDefender category", " / BitDefender domain info", " / Categories", " / Comodo Valkyrie Verdict category", " / detected_communicating_samples", " / detected_downloaded_samples", " / detected_referrer_samples", " / detected_urls", " / domain_siblings", " / Dr.Web category", " / Forcepoint ThreatSeeker category", " / Opera domain info", " / Pcaps", " / Resolutions", " / Sophos category", " / subdomains", " / TrendMicro category", " / undetected_communicating_samples", " / undetected_downloaded_samples", " / undetected_referrer_samples", " / undetected_urls", " / Websense ThreatSeeker category", " / Webutation domain info", " / whois", " / whois_timestamp", " / WOT domain info", " / Xcitium Verdict Cloud category");

        DomainReport report = await VirusTotal.GetDomainReportAsync(TestData.GetUnknownDomains(1).First());
        Assert.Equal(DomainResponseCode.NotPresent, report.ResponseCode);
    }
}