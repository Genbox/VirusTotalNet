using System;
using System.IO;
using System.Threading.Tasks;
using UnitTests.TestInternals;
using VirusTotalNET;
using VirusTotalNET.ResponseCodes;
using VirusTotalNET.Results;
using Xunit;

namespace UnitTests
{
    public class FileRescanTests : TestBase
    {
        [Fact]
        public async Task RescanKnownFile()
        {
            //Create the EICAR test virus. See http://www.eicar.org/86-0-Intended-use.html
            FileInfo fileInfo = new FileInfo("EICAR.txt");
            File.WriteAllText(fileInfo.FullName, @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

            RescanResult fileResult = await VirusTotal.RescanFile(fileInfo);

            //It should always be in the VirusTotal database. We expect it to rescan it
            Assert.Equal(ScanResponseCode.Queued, fileResult.ResponseCode);
        }

        [Fact]
        public void RescanMultipleKnownFile()
        {
            //TODO
        }

        [Fact]
        public async Task RescanUnknownFile()
        {
            IgnoreMissingJson(" / Permalink", " / scan_id", " / SHA256");

            FileInfo fileInfo = new FileInfo("VirusTotal.NET-Test.txt");
            File.WriteAllText(fileInfo.FullName, "VirusTotal.NET" + Guid.NewGuid());

            RescanResult fileResult = await VirusTotal.RescanFile(fileInfo);

            //It should not be in the VirusTotal database already, which means it should return error.
            Assert.Equal(ScanResponseCode.Error, fileResult.ResponseCode);
        }

        [Fact]
        public void RescanMultipleUnknownFile()
        {
            //TODO
        }

        [Fact]
        public async Task RescanSmallFile()
        {
            ScanResult fileResult = await VirusTotal.ScanFile(new byte[1], "VirusTotal.NET-Test.txt");

            //It has been scanned before, we expect it to return queued.
            Assert.Equal(ScanResponseCode.Queued, fileResult.ResponseCode);
        }

        [Fact]
        public async Task RescanLargeFile()
        {
            IgnoreMissingJson(" / Permalink", " / scan_id", " / SHA256");

            //Since rescan works on hashes, we expect the hash of this empty file (which is larger than the limit) is not present in the database.
            byte[] bytes = new byte[99 * 1023 * 1024]; //the weird size is because VT has some weird empty files in its database.
            string hash = HashHelper.GetMD5(bytes);
            RescanResult result = await VirusTotal.RescanFile(hash);
            Assert.Equal(ScanResponseCode.Error, result.ResponseCode);
        }
    }
}
