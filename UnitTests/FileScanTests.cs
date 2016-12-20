using System;
using System.IO;
using System.Threading.Tasks;
using UnitTests.TestInternals;
using VirusTotalNET.Exceptions;
using VirusTotalNET.ResponseCodes;
using VirusTotalNET.Results;
using Xunit;

namespace UnitTests
{
    public class FileScanTests : TestBase
    {
        [Fact]
        public async Task ScanKnownFile()
        {
            //Create the EICAR test virus. See http://www.eicar.org/86-0-Intended-use.html
            FileInfo fileInfo = new FileInfo("EICAR.txt");
            File.WriteAllText(fileInfo.FullName, @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

            ScanResult fileResult = await VirusTotal.ScanFile(fileInfo);

            //It should always be in the VirusTotal database.
            Assert.Equal(ScanResponseCode.Queued, fileResult.ResponseCode);
        }

        [Fact]
        public void ScanMultipleKnownFile()
        {
            //TODO
        }

        [Fact]
        public async Task ScanUnknownFile()
        {
            string guid = "VirusTotal.NET" + Guid.NewGuid();

            FileInfo fileInfo = new FileInfo("VirusTotal.NET-Test.txt");
            File.WriteAllText(fileInfo.FullName, guid);

            ScanResult fileResult = await VirusTotal.ScanFile(fileInfo);

            //It should never be in the VirusTotal database.
            Assert.Equal(ScanResponseCode.Queued, fileResult.ResponseCode);
        }

        [Fact]
        public void ScanMultipleUnknownFile()
        {
            //TODO
        }

        [Fact]
        public async Task ScanSmallFile()
        {
            ScanResult fileResult = await VirusTotal.ScanFile(new byte[1], "VirusTotal.NET-Test.txt");

            //It has been scanned before, we expect it to return queued.
            Assert.Equal(ScanResponseCode.Queued, fileResult.ResponseCode);
        }

        [Fact]
        public async Task ScanLargeFile()
        {
            //We expect it to throw a SizeLimitException because the file is above the legal limit
            await Assert.ThrowsAsync<SizeLimitException>(async () => await VirusTotal.ScanFile(new byte[VirusTotal.FileSizeLimit + 1], "VirusTotal.NET-Test.txt"));
        }

        [Fact]
        public async Task ScanLargeFile2()
        {
            VirusTotal.Timeout = TimeSpan.FromSeconds(250);
            ScanResult result = await VirusTotal.ScanFile(new byte[VirusTotal.FileSizeLimit], "VirusTotal.NET-Test.txt");

            Assert.Equal(ScanResponseCode.Queued, result.ResponseCode);
            Assert.False(string.IsNullOrWhiteSpace(result.ScanId));
        }
    }
}