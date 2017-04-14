using System;
using System.IO;
using System.Threading.Tasks;
using VirusTotalNET.Exceptions;
using VirusTotalNET.ResponseCodes;
using VirusTotalNET.Results;
using VirusTotalNET.UnitTests.TestInternals;
using Xunit;

namespace VirusTotalNET.UnitTests
{
    public class FileReportTests : TestBase
    {
        [Fact]
        public async Task GetReportForKnownFile()
        {
            IgnoreMissingJson("scans.Ad-Aware / Detail", "scans.AegisLab / Detail", "scans.AhnLab-V3 / Detail", "scans.ALYac / Detail", "scans.Antiy-AVL / Detail", "scans.Arcabit / Detail", "scans.Avast / Detail", "scans.AVG / Detail", "scans.Avira / Detail", "scans.AVware / Detail", "scans.Baidu / Detail", "scans.BitDefender / Detail", "scans.Bkav / Detail", "scans.CAT-QuickHeal / Detail", "scans.ClamAV / Detail", "scans.CMC / Detail", "scans.Comodo / Detail", "scans.Cyren / Detail", "scans.DrWeb / Detail", "scans.Emsisoft / Detail", "scans.Endgame / Detail", "scans.ESET-NOD32 / Detail", "scans.Fortinet / Detail", "scans.F-Prot / Detail", "scans.F-Secure / Detail", "scans.GData / Detail", "scans.Ikarus / Detail", "scans.Jiangmin / Detail", "scans.K7AntiVirus / Detail", "scans.K7GW / Detail", "scans.Kaspersky / Detail", "scans.Kingsoft / Detail", "scans.Malwarebytes / Detail", "scans.McAfee / Detail", "scans.McAfee-GW-Edition / Detail", "scans.Microsoft / Detail", "scans.MicroWorld-eScan / Detail", "scans.NANO-Antivirus / Detail", "scans.nProtect / Detail", "scans.Panda / Detail", "scans.Qihoo-360 / Detail", "scans.Rising / Detail", "scans.Sophos / Detail", "scans.SUPERAntiSpyware / Detail", "scans.Symantec / Detail", "scans.SymantecMobileInsight / Detail", "scans.Tencent / Detail", "scans.TheHacker / Detail", "scans.TotalDefense / Detail", "scans.TrendMicro / Detail", "scans.TrendMicro-HouseCall / Detail", "scans.VBA32 / Detail", "scans.VIPRE / Detail", "scans.ViRobot / Detail", "scans.Webroot / Detail", "scans.WhiteArmor / Detail", "scans.Yandex / Detail", "scans.Zillya / Detail", "scans.ZoneAlarm / Detail", "scans.Zoner / Detail");

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
            IgnoreMissingJson(" / MD5", " / Permalink", " / Positives", " / scan_date", " / scan_id", " / Scans", " / SHA1", " / SHA256", " / Total");

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
            IgnoreMissingJson(" / MD5", " / Permalink", " / Positives", " / scan_date", " / Scans", " / SHA1", " / SHA256", " / Total");

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