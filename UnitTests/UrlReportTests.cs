using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using VirusTotalNET.Exceptions;
using VirusTotalNET.ResponseCodes;
using VirusTotalNET.Results;
using VirusTotalNET.UnitTests.TestInternals;
using Xunit;

namespace VirusTotalNET.UnitTests
{
    public class UrlReportTests : TestBase
    {
        [Fact]
        public async Task GetReportKnownUrl()
        {
            IgnoreMissingJson("scans.ADMINUSLabs / Detail", "scans.AlienVault / Detail", "scans.Antiy-AVL / Detail", "scans.AutoShun / Detail", "scans.Avira / Detail", "scans.Baidu-International / Detail", "scans.BitDefender / Detail", "scans.Blueliv / Detail", "scans.Certly / Detail", "scans.C-SIRT / Detail", "scans.CyberCrime / Detail", "scans.Emsisoft / Detail", "scans.ESET / Detail", "scans.Fortinet / Detail", "scans.FraudScore / Detail", "scans.FraudSense / Detail", "scans.G-Data / Detail", "scans.K7AntiVirus / Detail", "scans.Kaspersky / Detail", "scans.Malekal / Detail", "scans.Malwared / Detail", "scans.MalwarePatrol / Detail", "scans.Netcraft / Detail", "scans.Nucleon / Detail", "scans.OpenPhish / Detail", "scans.Opera / Detail", "scans.PhishLabs / Detail", "scans.Phishtank / Detail", "scans.Quttera / Detail", "scans.Rising / Detail", "scans.SecureBrain / Detail", "scans.securolytics / Detail", "scans.Sophos / Detail", "scans.Spam404 / Detail", "scans.StopBadware / Detail", "scans.Tencent / Detail", "scans.ThreatHive / Detail", "scans.Trustwave / Detail", "scans.URLQuery / Detail", "scans.Webutation / Detail", "scans.ZCloudsec / Detail", "scans.ZeroCERT / Detail", "scans.Zerofox / Detail", "scans.zvelo / Detail", "scans['AegisLab WebGuard'] / Detail", "scans['CLEAN MX'] / Detail", "scans['Comodo Site Inspector'] / Detail", "scans['desenmascara.me'] / Detail", "scans['Dr.Web'] / Detail", "scans['Forcepoint ThreatSeeker'] / Detail", "scans['Google Safebrowsing'] / Detail", "scans['Malware Domain Blocklist'] / Detail", "scans['Malwarebytes hpHosts'] / Detail", "scans['malwares.com URL checker'] / Detail", "scans['SCUMWARE.org'] / Detail", "scans['Sucuri SiteCheck'] / Detail", "scans['Virusdie External Site Scan'] / Detail", "scans['VX Vault'] / Detail", "scans['Web Security Guard'] / Detail", "scans['ZDB Zeus'] / Detail");

            UrlReport urlReport = await VirusTotal.GetUrlReportAsync(TestData.KnownUrls.First());
            Assert.Equal(UrlReportResponseCode.Present, urlReport.ResponseCode);
        }

        [Fact]
        public async Task GetMultipleReportKnownUrl()
        {
            IgnoreMissingJson("[array].scans.ADMINUSLabs / Detail", "[array].scans.AlienVault / Detail", "[array].scans.Antiy-AVL / Detail", "[array].scans.AutoShun / Detail", "[array].scans.Avira / Detail", "[array].scans.Baidu-International / Detail", "[array].scans.BitDefender / Detail", "[array].scans.Blueliv / Detail", "[array].scans.Certly / Detail", "[array].scans.C-SIRT / Detail", "[array].scans.CyberCrime / Detail", "[array].scans.Emsisoft / Detail", "[array].scans.ESET / Detail", "[array].scans.Fortinet / Detail", "[array].scans.FraudScore / Detail", "[array].scans.FraudSense / Detail", "[array].scans.G-Data / Detail", "[array].scans.K7AntiVirus / Detail", "[array].scans.Kaspersky / Detail", "[array].scans.Malekal / Detail", "[array].scans.Malwared / Detail", "[array].scans.MalwarePatrol / Detail", "[array].scans.Netcraft / Detail", "[array].scans.Nucleon / Detail", "[array].scans.OpenPhish / Detail", "[array].scans.Opera / Detail", "[array].scans.ParetoLogic / Detail", "[array].scans.PhishLabs / Detail", "[array].scans.Phishtank / Detail", "[array].scans.Quttera / Detail", "[array].scans.Rising / Detail", "[array].scans.SecureBrain / Detail", "[array].scans.securolytics / Detail", "[array].scans.Sophos / Detail", "[array].scans.Spam404 / Detail", "[array].scans.StopBadware / Detail", "[array].scans.Tencent / Detail", "[array].scans.ThreatHive / Detail", "[array].scans.Trustwave / Detail", "[array].scans.URLQuery / Detail", "[array].scans.Webutation / Detail", "[array].scans.ZCloudsec / Detail", "[array].scans.ZeroCERT / Detail", "[array].scans.Zerofox / Detail", "[array].scans.zvelo / Detail", "[array].scans['AegisLab WebGuard'] / Detail", "[array].scans['CLEAN MX'] / Detail", "[array].scans['Comodo Site Inspector'] / Detail", "[array].scans['desenmascara.me'] / Detail", "[array].scans['Dr.Web'] / Detail", "[array].scans['Forcepoint ThreatSeeker'] / Detail", "[array].scans['Google Safebrowsing'] / Detail", "[array].scans['Malware Domain Blocklist'] / Detail", "[array].scans['Malwarebytes hpHosts'] / Detail", "[array].scans['malwares.com URL checker'] / Detail", "[array].scans['SCUMWARE.org'] / Detail", "[array].scans['Sucuri SiteCheck'] / Detail", "[array].scans['Virusdie External Site Scan'] / Detail", "[array].scans['VX Vault'] / Detail", "[array].scans['Web Security Guard'] / Detail", "[array].scans['ZDB Zeus'] / Detail");

            IEnumerable<UrlReport> urlReports = await VirusTotal.GetUrlReportsAsync(TestData.KnownUrls);

            foreach (UrlReport urlReport in urlReports)
            {
                Assert.Equal(UrlReportResponseCode.Present, urlReport.ResponseCode);
            }
        }

        [Fact]
        public async Task GetReportUnknownUrl()
        {
            IgnoreMissingJson(" / filescan_id", " / Permalink", " / Positives", " / scan_date", " / scan_id", " / Scans", " / Total", " / URL");

            UrlReport urlReport = await VirusTotal.GetUrlReportAsync(TestData.GetUnknownUrls(1).First());
            Assert.Equal(UrlReportResponseCode.NotPresent, urlReport.ResponseCode);

            //We are not supposed to have a scan id
            Assert.True(string.IsNullOrWhiteSpace(urlReport.ScanId));
        }

        [Fact]
        public async Task GetMultipleReportUnknownUrl()
        {
            IgnoreMissingJson("[array] / filescan_id", "[array] / Permalink", "[array] / Positives", "[array] / scan_date", "[array] / scan_id", "[array] / Scans", "[array] / Total", "[array] / URL");

            IEnumerable<UrlReport> urlReports = await VirusTotal.GetUrlReportsAsync(TestData.GetUnknownUrls(4));

            foreach (UrlReport urlReport in urlReports)
            {
                Assert.Equal(UrlReportResponseCode.NotPresent, urlReport.ResponseCode);
            }
        }

        [Fact]
        public async Task GetReportForUnknownUrlAndScan()
        {
            IgnoreMissingJson(" / filescan_id", " / Positives", " / Scans", " / Total");

            UrlReport urlReport = await VirusTotal.GetUrlReportAsync(TestData.GetUnknownUrls(1).First(), true);

            //It return "present" because we told it to scan it
            Assert.Equal(UrlReportResponseCode.Present, urlReport.ResponseCode);

            //We are supposed to have a scan id because we scanned it
            Assert.False(string.IsNullOrWhiteSpace(urlReport.ScanId));
        }

        [Fact]
        public async Task GetReportInvalidUrl()
        {
            await Assert.ThrowsAsync<InvalidResourceException>(async () => await VirusTotal.GetUrlReportAsync("."));
        }

        [Fact]
        public async Task UrlReportBatchLimit()
        {
            IgnoreMissingJson("[array] / filescan_id", "[array] / Permalink", "[array] / Positives", "[array] / scan_date", "[array] / scan_id", "[array] / Scans", "[array] / Total", "[array] / URL");

            VirusTotal.RestrictNumberOfResources = false;

            IEnumerable<UrlReport> results = await VirusTotal.GetUrlReportsAsync(TestData.GetUnknownUrls(5));

            //We only expect 4 as VT simply returns 4 results no matter the batch size.
            Assert.Equal(VirusTotal.UrlReportBatchSizeLimit, results.Count());
        }
    }
}