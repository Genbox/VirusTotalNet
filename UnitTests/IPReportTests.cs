using System.Threading.Tasks;
using UnitTests.TestInternals;
using VirusTotalNET.ResponseCodes;
using VirusTotalNET.Results;
using Xunit;

namespace UnitTests
{
    public class IPReportTests : TestBase
    {
        [Fact]
        public async Task GetIPReportKnownIP()
        {
            IPReport report = await VirusTotal.GetIPReport("8.8.8.8"); //Google DNS
            Assert.Equal(IPReportResponseCode.Present, report.ResponseCode);
        }
    }
}
