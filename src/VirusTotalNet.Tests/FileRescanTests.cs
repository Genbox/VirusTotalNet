using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using VirusTotalNet.ResponseCodes;
using VirusTotalNet.Results;
using VirusTotalNet.Tests.TestInternals;
using Xunit;

namespace VirusTotalNet.Tests;

public class FileRescanTests : TestBase
{
    [Fact(Skip = "Public keys no longer have access to this")]
    public async Task RescanKnownFile()
    {
        RescanResult fileResult = await VirusTotal.RescanFileAsync(TestData.EICARMalware);

        //It should always be in the VirusTotal database. We expect it to rescan it
        Assert.Equal(RescanResponseCode.Queued, fileResult.ResponseCode);
    }

    //[Fact]
    //public async Task RescanInvalidFile()
    //{
    //    //TODO: Can't seem to provoke an error response code.
    //}

    [Fact(Skip = "Public keys no longer have access to this")]
    public async Task RescanMultipleKnownFile()
    {
        IEnumerable<RescanResult> fileResult = await VirusTotal.RescanFilesAsync(TestData.KnownHashes);

        foreach (RescanResult rescanResult in fileResult)
        {
            //It should always be in the VirusTotal database. We expect it to rescan it
            Assert.Equal(RescanResponseCode.Queued, rescanResult.ResponseCode);
        }
    }

    [Fact(Skip = "Public keys no longer have access to this")]
    public async Task RescanUnknownFile()
    {
        IgnoreMissingJson(" / Permalink", " / scan_id", " / SHA256");

        RescanResult fileResult = await VirusTotal.RescanFileAsync(TestData.GetRandomSHA1s(1).First());

        //It should not be in the VirusTotal database already, which means it should return error.
        Assert.Equal(RescanResponseCode.ResourceNotFound, fileResult.ResponseCode);
    }

    [Fact(Skip = "Public keys no longer have access to this")]
    public async Task RescanSmallFile()
    {
        RescanResult fileResult = await VirusTotal.RescanFileAsync(new byte[1]);

        //It has been scanned before, we expect it to return queued.
        Assert.Equal(RescanResponseCode.Queued, fileResult.ResponseCode);
    }

    [Fact(Skip = "Public keys no longer have access to this")]
    public async Task RescanBatchLimit()
    {
        IgnoreMissingJson("[array] / Permalink", "[array] / scan_id", "[array] / SHA256");

        VirusTotal.RestrictNumberOfResources = false;

        IEnumerable<RescanResult> results = await VirusTotal.RescanFilesAsync(TestData.GetRandomSHA1s(50));

        //We only expect 25 as VT simply returns 25 results no matter the batch size.
        Assert.Equal(VirusTotal.RescanBatchSizeLimit, results.Count());
    }
}