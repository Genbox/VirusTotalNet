using System;
using System.IO;
using System.Threading.Tasks;
using VirusTotalNET;
using VirusTotalNET.Exceptions;
using VirusTotalNET.Objects;
using Xunit;

namespace UnitTests
{
    public class FileReportTests : TestBase
    {
        [Fact]
        public async Task GetReportForKnownFile()
        {
            //Create a hash of the EICAR test virus. See http://www.eicar.org/86-0-Intended-use.html
            string hash = HashHelper.GetMD5(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

            FileReport fileReport = await VirusTotal.GetFileReport(hash);

            //It should always be in the VirusTotal database.
            Assert.Equal(ReportResponseCode.Present, fileReport.ResponseCode);
        }

        [Fact]
        public void GetMultipleReportForKnownFile()
        {
            //TODO
        }

        [Fact]
        public async Task GetReportForUnknownFile()
        {
            string guid = "VirusTotal.NET" + Guid.NewGuid();

            FileInfo fileInfo = new FileInfo("VirusTotal.NET-Test.txt");
            File.WriteAllText(fileInfo.FullName, guid);

            FileReport fileReport = await VirusTotal.GetFileReport(fileInfo);

            //It should not be in the VirusTotal database already, which means it should return error.
            Assert.Equal(ReportResponseCode.NotPresent, fileReport.ResponseCode);
        }

        [Fact]
        public void GetMultipleReportForUnknownFile()
        {
            //TODO
        }

        [Fact]
        public async void GetReportForRecentFile()
        {
            //We create an unknown file
            string guid = "VirusTotal.NET" + Guid.NewGuid();

            FileInfo fileInfo = new FileInfo("VirusTotal.NET-Test.txt");
            File.WriteAllText(fileInfo.FullName, guid);

            //Attempt to submit it for scan
            ScanResult result = await VirusTotal.ScanFile(fileInfo);

            FileReport fileReport = await VirusTotal.GetFileReport(result.ScanId);

            //It should not be in the VirusTotal database already, which means it should return error.
            Assert.Equal(ReportResponseCode.StillQueued, fileReport.ResponseCode);
        }

        [Fact]
        public async void GetReportForInvalidResource()
        {
            await Assert.ThrowsAsync<InvalidResourceException>(async () => await VirusTotal.GetFileReport("aaaaaaaaaaa"));
        }
    }
}