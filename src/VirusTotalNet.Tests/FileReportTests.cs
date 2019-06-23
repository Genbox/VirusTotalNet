using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using VirusTotalNet.Exceptions;
using VirusTotalNet.ResponseCodes;
using VirusTotalNet.Results;
using VirusTotalNet.Tests.TestInternals;
using Xunit;

namespace VirusTotalNet.Tests
{
    public class FileReportTests : TestBase
    {
        [Fact]
        public async Task GetReportForKnownFile()
        {
            FileReport fileReport = await VirusTotal.GetFileReportAsync(TestData.EICARMalware);

            //It should always be in the VirusTotal database.
            Assert.Equal(FileReportResponseCode.Present, fileReport.ResponseCode);
        }

        //[Fact]
        //public async Task GetReportForInvalidFile()
        //{
        //    //TODO: I can't seem to provoke an error response code by sending resources that are invalid.
        //    //They just seem to either give code 0 (notpresent) or an empty JSON response
        //}

        [Fact]
        public async Task GetMultipleReportForKnownFiles()
        {
            IEnumerable<FileReport> results = await VirusTotal.GetFileReportsAsync(TestData.KnownHashes);

            foreach (FileReport fileReport in results)
            {
                //It should always be in the VirusTotal database.
                Assert.Equal(FileReportResponseCode.Present, fileReport.ResponseCode);
            }
        }

        [Fact]
        public async Task GetReportForUnknownFile()
        {
            //Reports for unknown files do not have these fields
            IgnoreMissingJson(" / MD5", " / Permalink", " / Positives", " / scan_date", " / scan_id", " / Scans", " / SHA1", " / SHA256", " / Total");

            FileReport fileReport = await VirusTotal.GetFileReportAsync(TestData.GetRandomSHA1s(1).First());

            //It should not be in the VirusTotal database already, which means it should return error.
            Assert.Equal(FileReportResponseCode.NotPresent, fileReport.ResponseCode);
        }

        [Fact]
        public async Task GetMultipleReportForUnknownFiles()
        {
            //Reports for unknown files do not have these fields
            IgnoreMissingJson("[array] / MD5", "[array] / Permalink", "[array] / Positives", "[array] / scan_date", "[array] / scan_id", "[array] / Scans", "[array] / SHA1", "[array] / SHA256", "[array] / Total");

            IEnumerable<FileReport> results = await VirusTotal.GetFileReportsAsync(TestData.GetRandomSHA1s(3));

            foreach (FileReport fileReport in results)
            {
                //It should never be in the VirusTotal database.
                Assert.Equal(FileReportResponseCode.NotPresent, fileReport.ResponseCode);
            }
        }

        [Fact]
        public async void GetReportForRecentFile()
        {
            //We ignore these fields due to unknown file
            IgnoreMissingJson(" / MD5", " / Permalink", " / Positives", " / scan_date", " / Scans", " / SHA1", " / SHA256", " / Total");

            ScanResult result = await VirusTotal.ScanFileAsync(TestData.GetRandomFile(128, 1).First(), TestData.TestFileName);

            FileReport fileReport = await VirusTotal.GetFileReportAsync(result.ScanId);

            Assert.Equal(FileReportResponseCode.Queued, fileReport.ResponseCode);
        }

        [Fact]
        public async void GetReportForInvalidResource()
        {
            await Assert.ThrowsAsync<InvalidResourceException>(async () => await VirusTotal.GetFileReportAsync("aaaaaaaaaaa"));
        }

        [Fact]
        public async Task FileReportBatchLimit()
        {
            IgnoreMissingJson("[array] / MD5", "[array] / Permalink", "[array] / Positives", "[array] / scan_date", "[array] / scan_id", "[array] / Scans", "[array] / SHA1", "[array] / SHA256", "[array] / Total");

            VirusTotal.RestrictNumberOfResources = false;

            IEnumerable<FileReport> results = await VirusTotal.GetFileReportsAsync(TestData.GetRandomSHA1s(10));

            //We only expect 4 as VT simply returns 4 results no matter the batch size.
            Assert.Equal(VirusTotal.FileReportBatchSizeLimit, results.Count());
        }
    }
}