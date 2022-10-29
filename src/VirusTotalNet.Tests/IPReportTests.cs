using System.Linq;
using System.Threading.Tasks;
using VirusTotalNet.Exceptions;
using VirusTotalNet.ResponseCodes;
using VirusTotalNet.Results;
using VirusTotalNet.Tests.TestInternals;
using Xunit;

namespace VirusTotalNet.Tests;

public class IPReportTests : TestBase
{
    [Fact]
    public async Task GetIPReportKnownIPv4()
    {
        IgnoreMissingJson("detected_referrer_samples[array] / Date", " / Continent", " / Network");

        IPReport report = await VirusTotal.GetIPReportAsync(TestData.KnownIPv4s.First());
        Assert.Equal(IPReportResponseCode.Present, report.ResponseCode);
    }

    [Fact]
    public async Task GetIPReportRandomIPv6()
    {
        //IPv6 is not supported
        await Assert.ThrowsAsync<InvalidResourceException>(async () => await VirusTotal.GetIPReportAsync(TestData.GetRandomIPv6s(1).First()));
    }
}