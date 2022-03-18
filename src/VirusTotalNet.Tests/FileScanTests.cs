using System;
using System.Linq;
using System.Threading.Tasks;
using VirusTotalNet.Exceptions;
using VirusTotalNet.ResponseCodes;
using VirusTotalNet.Results;
using VirusTotalNet.Tests.TestInternals;
using Xunit;

namespace VirusTotalNet.Tests;

public class FileScanTests : TestBase
{
    [Fact]
    public async Task ScanKnownFile()
    {
        ScanResult fileResult = await VirusTotal.ScanFileAsync(TestData.EICARMalware, TestData.EICARFilename);

        //It should always be in the VirusTotal database.
        Assert.Equal(ScanFileResponseCode.Queued, fileResult.ResponseCode);
    }

    [Fact]
    public async Task ScanTestFile()
    {
        ScanResult fileResult = await VirusTotal.ScanFileAsync(TestData.TestFile, TestData.TestFileName);

        //It should always be in the VirusTotal database.
        Assert.Equal(ScanFileResponseCode.Queued, fileResult.ResponseCode);
    }

    [Fact]
    public async Task ScanUnknownFile()
    {
        ScanResult fileResult = await VirusTotal.ScanFileAsync(TestData.GetRandomFile(128, 1).First(), TestData.TestFileName);

        //It should never be in the VirusTotal database.
        Assert.Equal(ScanFileResponseCode.Queued, fileResult.ResponseCode);
    }

    [Fact]
    public async Task ScanSmallFile()
    {
        ScanResult fileResult = await VirusTotal.ScanFileAsync(new byte[1], TestData.TestFileName);
        Assert.Equal(ScanFileResponseCode.Queued, fileResult.ResponseCode);
    }

    [Fact]
    public async Task ScanLargeFile()
    {
        VirusTotal.Timeout = TimeSpan.FromSeconds(500);
        ScanResult result = await VirusTotal.ScanFileAsync(new byte[VirusTotal.FileSizeLimit], TestData.TestFileName);

        Assert.Equal(ScanFileResponseCode.Queued, result.ResponseCode);
    }

    [Fact]
    public async Task ScanLargeFileOverLimit()
    {
        //We expect it to throw a SizeLimitException because the file is above the legal limit
        await Assert.ThrowsAsync<SizeLimitException>(async () => await VirusTotal.ScanFileAsync(new byte[VirusTotal.FileSizeLimit + 1], TestData.TestFileName));
    }

    [Fact]
    public async Task ScanVeryLargeFile()
    {
        VirusTotal.Timeout = TimeSpan.FromSeconds(500);
        ScanResult result = await VirusTotal.ScanLargeFileAsync(new byte[VirusTotal.LargeFileSizeLimit], TestData.TestFileName);

        Assert.Equal(ScanFileResponseCode.Queued, result.ResponseCode);
    }

    [Fact]
    public async Task ScanVeryLargeFileOverLimit()
    {
        //We expect it to throw a SizeLimitException because the file is above the legal limit
        await Assert.ThrowsAsync<SizeLimitException>(async () => await VirusTotal.ScanFileAsync(new byte[VirusTotal.LargeFileSizeLimit + 1], TestData.TestFileName));
    }

    [Fact]
    public async Task ScanLargeFileOverLimitCheckDisabled()
    {
        VirusTotal.RestrictSizeLimits = false;
        VirusTotal.Timeout = TimeSpan.FromSeconds(500);

        //4KB over the limit should be enough. it is difficult to test since VT measures the limit on total request size.
        await Assert.ThrowsAsync<SizeLimitException>(async () => await VirusTotal.ScanFileAsync(new byte[VirusTotal.FileSizeLimit + 1024 * 4], TestData.TestFileName));
    }
}