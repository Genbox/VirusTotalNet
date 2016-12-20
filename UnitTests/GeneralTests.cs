using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using UnitTests.TestInternals;
using VirusTotalNET;
using VirusTotalNET.Exceptions;
using VirusTotalNET.Results;
using Xunit;

namespace UnitTests
{
    public class GeneralTests : TestBase
    {
        public GeneralTests()
        {
            //We turn off the limits
            VirusTotal.RestrictNumberOfResources = false;
        }

        [Fact]
        public async Task UnauthorizedScan()
        {
            VirusTotal virusTotal = new VirusTotal("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"); //64 characters
            await Assert.ThrowsAsync<AccessDeniedException>(async () => await virusTotal.GetFileReport("ca6d91bad9d5d5698c92dc64295a15a6")); //conficker MD5 hash
        }

        [Fact]
        public async void FileScanBatchLimit()
        {
            List<Tuple<byte[], string>> files = new List<Tuple<byte[], string>>();

            for (int i = 1; i <= 50; i++)
            {
                files.Add(new Tuple<byte[], string>(new byte[i], "test"));
            }

            ScanResult[] results = await Task.WhenAll(VirusTotal.ScanFiles(files));

            //We should be able to send as many files as we like (no limit)
            Assert.Equal(files.Count, results.Length);
        }

        [Fact]
        public async Task FileReportBatchLimit()
        {
            List<byte[]> files = new List<byte[]>();

            for (int i = 1; i <= 10; i++)
            {
                files.Add(new byte[i]);
            }

            List<FileReport> results = await VirusTotal.GetFileReports(files);

            //We only expect 4 as VT simply returns 4 results no matter the batch size.
            Assert.Equal(4, results.Count);
        }

        [Fact]
        public async Task UrlScanBatchLimit()
        {
            List<string> urls = new List<string>();

            for (int i = 1; i <= 30; i++)
            {
                urls.Add(i + ".com");
            }

            List<UrlScanResult> results = await VirusTotal.ScanUrls(urls);

            //We only expect 25 as VT simply returns 25 results no matter the batch size.
            Assert.Equal(25, results.Count);
        }

        [Fact]
        public async Task UrlReportBatchLimit()
        {
            List<string> urls = new List<string>();

            for (int i = 1; i <= 10; i++)
            {
                urls.Add(i + ".com");
            }

            List<UrlReport> results = await VirusTotal.GetUrlReports(urls);

            //We only expect 4 as VT simply returns 4 results no matter the batch size.
            Assert.Equal(4, results.Count);
        }

        [Fact]
        public async Task IPReportBatchLimit()
        {
            List<string> ips = new List<string>();

            for (int i = 1; i <= 5; i++)
            {
                ips.Add("8.8.8." + i);
            }

            //We can't do 5 requests pr. minute, so we expect this to throw an error.
            await Assert.ThrowsAsync<RateLimitException>(async () => await Task.WhenAll(VirusTotal.GetIPReports(ips)));
        }

        [Fact]
        public async Task DomainReportBatchLimit()
        {
            List<string> domains = new List<string>();

            for (int i = 1; i <= 5; i++)
            {
                domains.Add("google" + i + ".com");
            }

            //We can't do 5 requests pr. minute, so we expect this to throw an error.
            await Assert.ThrowsAsync<RateLimitException>(async () => await Task.WhenAll(VirusTotal.GetDomainReports(domains)));
        }
    }
}
