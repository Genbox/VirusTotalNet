using System.Linq;
using System.Threading.Tasks;
using VirusTotalNet.Exceptions;
using VirusTotalNet.Tests.TestInternals;
using Xunit;

namespace VirusTotalNet.Tests;

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

    [Fact]
    public void PublicFileLink()
    {
        //By default, VirusTotal redirects to http:// based links
        VirusTotal.UseTLS = false;

        Assert.Equal("http://www.virustotal.com/#/file/99017f6eebbac24f351415dd410d522d/detection", VirusTotal.GetPublicFileScanLink("99017f6eebbac24f351415dd410d522d"));
        Assert.Equal("http://www.virustotal.com/#/file/4d1740485713a2ab3a4f5822a01f645fe8387f92/detection", VirusTotal.GetPublicFileScanLink("4d1740485713a2ab3a4f5822a01f645fe8387f92"));
        Assert.Equal("http://www.virustotal.com/#/file/52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c/detection", VirusTotal.GetPublicFileScanLink("52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c"));
    }

    [Fact]
    public void PublicUrlLink()
    {
        //By default, VirusTotal redirects to http:// based links
        VirusTotal.UseTLS = false;

        Assert.Equal("http://www.virustotal.com/#/url/cf4b367e49bf0b22041c6f065f4aa19f3cfe39c8d5abc0617343d1a66c6a26f5/detection", VirusTotal.GetPublicUrlScanLink("google.com"));
        Assert.Equal("http://www.virustotal.com/#/url/cf4b367e49bf0b22041c6f065f4aa19f3cfe39c8d5abc0617343d1a66c6a26f5/detection", VirusTotal.GetPublicUrlScanLink("http://google.com"));
        Assert.Equal("http://www.virustotal.com/#/url/9d116b1b0c1200ca75016e4c010bc94836366881b021a658ea7f8548b6543c1e/detection", VirusTotal.GetPublicUrlScanLink("https://google.com"));
    }
}