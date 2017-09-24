using System.Linq;
using System.Threading.Tasks;
using VirusTotalNET.Exceptions;
using VirusTotalNET.UnitTests.TestInternals;
using Xunit;

namespace VirusTotalNET.UnitTests
{
    public class GeneralTests : TestBase
    {
        [Fact]
        public async Task UnauthorizedScan()
        {
            VirusTotal virusTotal = new VirusTotal("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"); //64 characters
            await Assert.ThrowsAsync<AccessDeniedException>(async () => await virusTotal.GetFileReportAsync(TestData.KnownHashes.First()));
        }

        [Fact]
        public async Task GetRawResponse()
        {
            bool completedRaised = false;

            VirusTotal.OnRawResponseReceived += response =>
            {
                Assert.NotEmpty(response);
                completedRaised = true;
            };

            await VirusTotal.GetFileReportAsync(TestData.KnownHashes.First());
            Assert.True(completedRaised);
        }

        [Fact]
        public async Task OnHTTPRequest()
        {
            bool completedRaised = false;

            VirusTotal.OnHTTPRequestSending += request =>
            {
                Assert.NotNull(request);
                completedRaised = true;
            };

            await VirusTotal.GetFileReportAsync(TestData.KnownHashes.First());
            Assert.True(completedRaised);
        }

        [Fact]
        public async Task OnHTTPResponse()
        {
            bool completedRaised = false;

            VirusTotal.OnHTTPResponseReceived += response =>
            {
                Assert.NotNull(response);
                completedRaised = true;
            };

            await VirusTotal.GetFileReportAsync(TestData.KnownHashes.First());
            Assert.True(completedRaised);
        }
    }
}