using System.Threading.Tasks;
using VirusTotalNET.ResponseCodes;
using VirusTotalNET.Results;
using VirusTotalNET.UnitTests.TestInternals;
using Xunit;

namespace VirusTotalNET.UnitTests
{
    public class IPReportTests : TestBase
    {
        [Fact]
        public async Task GetIPReportKnownIP()
        {
            IgnoreMissingJson("detected_referrer_samples[array] / Date", "resolutions[array] / ip_address", "undetected_referrer_samples[array] / Date");

            IPReport report = await VirusTotal.GetIPReport("8.8.8.8"); //Google DNS
            Assert.Equal(IPReportResponseCode.Present, report.ResponseCode);
        }
    }
}
