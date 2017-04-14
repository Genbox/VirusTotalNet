using System;
using System.Collections.Generic;
using System.Threading.Tasks;
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
            IgnoreMissingJson("scans.ADMINUSLabs / Detail", "scans.ADMINUSLabs / Update", "scans.ADMINUSLabs / Version", "scans.AlienVault / Detail", "scans.AlienVault / Update", "scans.AlienVault / Version", "scans.Antiy-AVL / Detail", "scans.Antiy-AVL / Update", "scans.Antiy-AVL / Version", "scans.AutoShun / Detail", "scans.AutoShun / Update", "scans.AutoShun / Version", "scans.Avira / Detail", "scans.Avira / Update", "scans.Avira / Version", "scans.Baidu-International / Detail", "scans.Baidu-International / Update", "scans.Baidu-International / Version", "scans.BitDefender / Detail", "scans.BitDefender / Update", "scans.BitDefender / Version", "scans.Blueliv / Detail", "scans.Blueliv / Update", "scans.Blueliv / Version", "scans.Certly / Detail", "scans.Certly / Update", "scans.Certly / Version", "scans.C-SIRT / Detail", "scans.C-SIRT / Update", "scans.C-SIRT / Version", "scans.CyberCrime / Detail", "scans.CyberCrime / Update", "scans.CyberCrime / Version", "scans.Emsisoft / Detail", "scans.Emsisoft / Update", "scans.Emsisoft / Version", "scans.ESET / Detail", "scans.ESET / Update", "scans.ESET / Version", "scans.Fortinet / Detail", "scans.Fortinet / Update", "scans.Fortinet / Version", "scans.FraudScore / Detail", "scans.FraudScore / Update", "scans.FraudScore / Version", "scans.FraudSense / Detail", "scans.FraudSense / Update", "scans.FraudSense / Version", "scans.G-Data / Detail", "scans.G-Data / Update", "scans.G-Data / Version", "scans.K7AntiVirus / Detail", "scans.K7AntiVirus / Update", "scans.K7AntiVirus / Version", "scans.Kaspersky / Detail", "scans.Kaspersky / Update", "scans.Kaspersky / Version", "scans.Malekal / Detail", "scans.Malekal / Update", "scans.Malekal / Version", "scans.Malwared / Detail", "scans.Malwared / Update", "scans.Malwared / Version", "scans.MalwareDomainList / Update", "scans.MalwareDomainList / Version", "scans.MalwarePatrol / Detail", "scans.MalwarePatrol / Update", "scans.MalwarePatrol / Version", "scans.Netcraft / Detail", "scans.Netcraft / Update", "scans.Netcraft / Version", "scans.Nucleon / Detail", "scans.Nucleon / Update", "scans.Nucleon / Version", "scans.OpenPhish / Detail", "scans.OpenPhish / Update", "scans.OpenPhish / Version", "scans.Opera / Detail", "scans.Opera / Update", "scans.Opera / Version", "scans.ParetoLogic / Detail", "scans.ParetoLogic / Update", "scans.ParetoLogic / Version", "scans.PhishLabs / Detail", "scans.PhishLabs / Update", "scans.PhishLabs / Version", "scans.Phishtank / Detail", "scans.Phishtank / Update", "scans.Phishtank / Version", "scans.Quttera / Detail", "scans.Quttera / Update", "scans.Quttera / Version", "scans.Rising / Detail", "scans.Rising / Update", "scans.Rising / Version", "scans.SecureBrain / Detail", "scans.SecureBrain / Update", "scans.SecureBrain / Version", "scans.securolytics / Detail", "scans.securolytics / Update", "scans.securolytics / Version", "scans.Sophos / Detail", "scans.Sophos / Update", "scans.Sophos / Version", "scans.Spam404 / Detail", "scans.Spam404 / Update", "scans.Spam404 / Version", "scans.StopBadware / Detail", "scans.StopBadware / Update", "scans.StopBadware / Version", "scans.Tencent / Detail", "scans.Tencent / Update", "scans.Tencent / Version", "scans.ThreatHive / Detail", "scans.ThreatHive / Update", "scans.ThreatHive / Version", "scans.Trustwave / Detail", "scans.Trustwave / Update", "scans.Trustwave / Version", "scans.URLQuery / Detail", "scans.URLQuery / Update", "scans.URLQuery / Version", "scans.Webutation / Detail", "scans.Webutation / Update", "scans.Webutation / Version", "scans.ZCloudsec / Detail", "scans.ZCloudsec / Update", "scans.ZCloudsec / Version", "scans.ZeroCERT / Detail", "scans.ZeroCERT / Update", "scans.ZeroCERT / Version", "scans.Zerofox / Detail", "scans.Zerofox / Update", "scans.Zerofox / Version", "scans.ZeusTracker / Update", "scans.ZeusTracker / Version", "scans.zvelo / Detail", "scans.zvelo / Update", "scans.zvelo / Version", "scans['AegisLab WebGuard'] / Detail", "scans['AegisLab WebGuard'] / Update", "scans['AegisLab WebGuard'] / Version", "scans['CLEAN MX'] / Detail", "scans['CLEAN MX'] / Update", "scans['CLEAN MX'] / Version", "scans['Comodo Site Inspector'] / Detail", "scans['Comodo Site Inspector'] / Update", "scans['Comodo Site Inspector'] / Version", "scans['desenmascara.me'] / Detail", "scans['desenmascara.me'] / Update", "scans['desenmascara.me'] / Version", "scans['Dr.Web'] / Detail", "scans['Dr.Web'] / Update", "scans['Dr.Web'] / Version", "scans['Google Safebrowsing'] / Detail", "scans['Google Safebrowsing'] / Update", "scans['Google Safebrowsing'] / Version", "scans['Malc0de Database'] / Update", "scans['Malc0de Database'] / Version", "scans['Malware Domain Blocklist'] / Detail", "scans['Malware Domain Blocklist'] / Update", "scans['Malware Domain Blocklist'] / Version", "scans['Malwarebytes hpHosts'] / Detail", "scans['Malwarebytes hpHosts'] / Update", "scans['Malwarebytes hpHosts'] / Version", "scans['malwares.com URL checker'] / Detail", "scans['malwares.com URL checker'] / Update", "scans['malwares.com URL checker'] / Version", "scans['SCUMWARE.org'] / Detail", "scans['SCUMWARE.org'] / Update", "scans['SCUMWARE.org'] / Version", "scans['Sucuri SiteCheck'] / Detail", "scans['Sucuri SiteCheck'] / Update", "scans['Sucuri SiteCheck'] / Version", "scans['VX Vault'] / Detail", "scans['VX Vault'] / Update", "scans['VX Vault'] / Version", "scans['Web Security Guard'] / Detail", "scans['Web Security Guard'] / Update", "scans['Web Security Guard'] / Version", "scans['Websense ThreatSeeker'] / Detail", "scans['Websense ThreatSeeker'] / Update", "scans['Websense ThreatSeeker'] / Version", "scans['Yandex Safebrowsing'] / Update", "scans['Yandex Safebrowsing'] / Version", "scans['ZDB Zeus'] / Detail", "scans['ZDB Zeus'] / Update", "scans['ZDB Zeus'] / Version");

            UrlReport urlReport = await VirusTotal.GetUrlReport("google.com");
            Assert.Equal(ReportResponseCode.Present, urlReport.ResponseCode);
        }

        [Fact]
        public async Task GetMultipleReportKnownUrl()
        {
            IgnoreMissingJson("[array].scans.ADMINUSLabs / Detail", "[array].scans.ADMINUSLabs / Update", "[array].scans.ADMINUSLabs / Version", "[array].scans.AlienVault / Detail", "[array].scans.AlienVault / Update", "[array].scans.AlienVault / Version", "[array].scans.Antiy-AVL / Detail", "[array].scans.Antiy-AVL / Update", "[array].scans.Antiy-AVL / Version", "[array].scans.AutoShun / Detail", "[array].scans.AutoShun / Update", "[array].scans.AutoShun / Version", "[array].scans.Avira / Detail", "[array].scans.Avira / Update", "[array].scans.Avira / Version", "[array].scans.Baidu-International / Detail", "[array].scans.Baidu-International / Update", "[array].scans.Baidu-International / Version", "[array].scans.BitDefender / Detail", "[array].scans.BitDefender / Update", "[array].scans.BitDefender / Version", "[array].scans.Blueliv / Detail", "[array].scans.Blueliv / Update", "[array].scans.Blueliv / Version", "[array].scans.Certly / Detail", "[array].scans.Certly / Update", "[array].scans.Certly / Version", "[array].scans.CRDF / Detail", "[array].scans.CRDF / Update", "[array].scans.CRDF / Version", "[array].scans.C-SIRT / Detail", "[array].scans.C-SIRT / Update", "[array].scans.C-SIRT / Version", "[array].scans.CyberCrime / Detail", "[array].scans.CyberCrime / Update", "[array].scans.CyberCrime / Version", "[array].scans.Emsisoft / Detail", "[array].scans.Emsisoft / Update", "[array].scans.Emsisoft / Version", "[array].scans.ESET / Detail", "[array].scans.ESET / Update", "[array].scans.ESET / Version", "[array].scans.Fortinet / Detail", "[array].scans.Fortinet / Update", "[array].scans.Fortinet / Version", "[array].scans.FraudScore / Detail", "[array].scans.FraudScore / Update", "[array].scans.FraudScore / Version", "[array].scans.FraudSense / Detail", "[array].scans.FraudSense / Update", "[array].scans.FraudSense / Version", "[array].scans.G-Data / Detail", "[array].scans.G-Data / Update", "[array].scans.G-Data / Version", "[array].scans.K7AntiVirus / Detail", "[array].scans.K7AntiVirus / Update", "[array].scans.K7AntiVirus / Version", "[array].scans.Kaspersky / Detail", "[array].scans.Kaspersky / Update", "[array].scans.Kaspersky / Version", "[array].scans.Malekal / Detail", "[array].scans.Malekal / Update", "[array].scans.Malekal / Version", "[array].scans.Malwared / Detail", "[array].scans.Malwared / Update", "[array].scans.Malwared / Version", "[array].scans.MalwareDomainList / Update", "[array].scans.MalwareDomainList / Version", "[array].scans.MalwarePatrol / Detail", "[array].scans.MalwarePatrol / Update", "[array].scans.MalwarePatrol / Version", "[array].scans.Netcraft / Detail", "[array].scans.Netcraft / Update", "[array].scans.Netcraft / Version", "[array].scans.Nucleon / Detail", "[array].scans.Nucleon / Update", "[array].scans.Nucleon / Version", "[array].scans.OpenPhish / Detail", "[array].scans.OpenPhish / Update", "[array].scans.OpenPhish / Version", "[array].scans.Opera / Detail", "[array].scans.Opera / Update", "[array].scans.Opera / Version", "[array].scans.PalevoTracker / Detail", "[array].scans.PalevoTracker / Update", "[array].scans.PalevoTracker / Version", "[array].scans.ParetoLogic / Detail", "[array].scans.ParetoLogic / Update", "[array].scans.ParetoLogic / Version", "[array].scans.PhishLabs / Detail", "[array].scans.PhishLabs / Update", "[array].scans.PhishLabs / Version", "[array].scans.Phishtank / Detail", "[array].scans.Phishtank / Update", "[array].scans.Phishtank / Version", "[array].scans.Quttera / Detail", "[array].scans.Quttera / Update", "[array].scans.Quttera / Version", "[array].scans.Rising / Detail", "[array].scans.Rising / Update", "[array].scans.Rising / Version", "[array].scans.Sangfor / Detail", "[array].scans.Sangfor / Update", "[array].scans.Sangfor / Version", "[array].scans.SecureBrain / Detail", "[array].scans.SecureBrain / Update", "[array].scans.SecureBrain / Version", "[array].scans.securolytics / Detail", "[array].scans.securolytics / Update", "[array].scans.securolytics / Version", "[array].scans.Sophos / Detail", "[array].scans.Sophos / Update", "[array].scans.Sophos / Version", "[array].scans.Spam404 / Detail", "[array].scans.Spam404 / Update", "[array].scans.Spam404 / Version", "[array].scans.SpyEyeTracker / Update", "[array].scans.SpyEyeTracker / Version", "[array].scans.StopBadware / Detail", "[array].scans.StopBadware / Update", "[array].scans.StopBadware / Version", "[array].scans.Tencent / Detail", "[array].scans.Tencent / Update", "[array].scans.Tencent / Version", "[array].scans.ThreatHive / Detail", "[array].scans.ThreatHive / Update", "[array].scans.ThreatHive / Version", "[array].scans.Trustwave / Detail", "[array].scans.Trustwave / Update", "[array].scans.Trustwave / Version", "[array].scans.URLQuery / Detail", "[array].scans.URLQuery / Update", "[array].scans.URLQuery / Version", "[array].scans.Webutation / Detail", "[array].scans.Webutation / Update", "[array].scans.Webutation / Version", "[array].scans.Wepawet / Detail", "[array].scans.Wepawet / Update", "[array].scans.Wepawet / Version", "[array].scans.ZCloudsec / Detail", "[array].scans.ZCloudsec / Update", "[array].scans.ZCloudsec / Version", "[array].scans.ZeroCERT / Detail", "[array].scans.ZeroCERT / Update", "[array].scans.ZeroCERT / Version", "[array].scans.Zerofox / Detail", "[array].scans.Zerofox / Update", "[array].scans.Zerofox / Version", "[array].scans.ZeusTracker / Update", "[array].scans.ZeusTracker / Version", "[array].scans.zvelo / Detail", "[array].scans.zvelo / Update", "[array].scans.zvelo / Version", "[array].scans['AegisLab WebGuard'] / Detail", "[array].scans['AegisLab WebGuard'] / Update", "[array].scans['AegisLab WebGuard'] / Version", "[array].scans['CLEAN MX'] / Detail", "[array].scans['CLEAN MX'] / Update", "[array].scans['CLEAN MX'] / Version", "[array].scans['Comodo Site Inspector'] / Detail", "[array].scans['Comodo Site Inspector'] / Update", "[array].scans['Comodo Site Inspector'] / Version", "[array].scans['desenmascara.me'] / Detail", "[array].scans['desenmascara.me'] / Update", "[array].scans['desenmascara.me'] / Version", "[array].scans['Dr.Web'] / Detail", "[array].scans['Dr.Web'] / Update", "[array].scans['Dr.Web'] / Version", "[array].scans['Google Safebrowsing'] / Detail", "[array].scans['Google Safebrowsing'] / Update", "[array].scans['Google Safebrowsing'] / Version", "[array].scans['Malc0de Database'] / Update", "[array].scans['Malc0de Database'] / Version", "[array].scans['Malware Domain Blocklist'] / Detail", "[array].scans['Malware Domain Blocklist'] / Update", "[array].scans['Malware Domain Blocklist'] / Version", "[array].scans['Malwarebytes hpHosts'] / Detail", "[array].scans['Malwarebytes hpHosts'] / Update", "[array].scans['Malwarebytes hpHosts'] / Version", "[array].scans['malwares.com URL checker'] / Detail", "[array].scans['malwares.com URL checker'] / Update", "[array].scans['malwares.com URL checker'] / Version", "[array].scans['SCUMWARE.org'] / Detail", "[array].scans['SCUMWARE.org'] / Update", "[array].scans['SCUMWARE.org'] / Version", "[array].scans['Sucuri SiteCheck'] / Detail", "[array].scans['Sucuri SiteCheck'] / Update", "[array].scans['Sucuri SiteCheck'] / Version", "[array].scans['VX Vault'] / Detail", "[array].scans['VX Vault'] / Update", "[array].scans['VX Vault'] / Version", "[array].scans['Web Security Guard'] / Detail", "[array].scans['Web Security Guard'] / Update", "[array].scans['Web Security Guard'] / Version", "[array].scans['Websense ThreatSeeker'] / Detail", "[array].scans['Websense ThreatSeeker'] / Update", "[array].scans['Websense ThreatSeeker'] / Version", "[array].scans['Yandex Safebrowsing'] / Update", "[array].scans['Yandex Safebrowsing'] / Version", "[array].scans['ZDB Zeus'] / Detail", "[array].scans['ZDB Zeus'] / Update", "[array].scans['ZDB Zeus'] / Version");

            string[] urls = { "google.se", "http://google.com", "https://virustotal.com" };

            List<UrlReport> urlReports = await VirusTotal.GetUrlReports(urls);

            foreach (UrlReport urlReport in urlReports)
            {
                Assert.Equal(ReportResponseCode.Present, urlReport.ResponseCode);
            }
        }

        [Fact]
        public async Task GetReportUnknownUrl()
        {
            IgnoreMissingJson(" / filescan_id", " / Permalink", " / Positives", " / scan_date", " / scan_id", " / Scans", " / Total", " / URL");

            UrlReport urlReport = await VirusTotal.GetUrlReport("VirusTotal.NET" + Guid.NewGuid() + ".com");
            Assert.Equal(ReportResponseCode.NotPresent, urlReport.ResponseCode);

            //We are not supposed to have a scan id
            Assert.True(string.IsNullOrWhiteSpace(urlReport.ScanId));
        }

        [Fact]
        public async Task GetMultipleReportUnknownUrl()
        {
            IgnoreMissingJson("[array] / filescan_id", "[array] / Permalink", "[array] / Positives", "[array] / scan_date", "[array] / scan_id", "[array] / Scans", "[array] / Total", "[array] / URL");

            string[] urls = { "VirusTotal.NET" + Guid.NewGuid() + ".com", "VirusTotal.NET" + Guid.NewGuid() + ".com", "VirusTotal.NET" + Guid.NewGuid() + ".com" };

            List<UrlReport> urlReports = await VirusTotal.GetUrlReports(urls);

            foreach (UrlReport urlReport in urlReports)
            {
                Assert.Equal(ReportResponseCode.NotPresent, urlReport.ResponseCode);
            }
        }

        [Fact]
        public async Task GetReportForUnknownUrlAndScan()
        {
            IgnoreMissingJson(" / filescan_id", " / Positives", " / Scans", " / Total");

            UrlReport urlReport = await VirusTotal.GetUrlReport("VirusTotal.NET" + Guid.NewGuid() + ".com", true);

            //It return "present" because we told it to scan it
            Assert.Equal(ReportResponseCode.Present, urlReport.ResponseCode);

            //We are supposed to have a scan id because we scanned it
            Assert.False(string.IsNullOrWhiteSpace(urlReport.ScanId));
        }

        [Fact]
        public async Task GetReportInvalidUrl()
        {
            await Assert.ThrowsAsync<Exception>(async () => await VirusTotal.GetUrlReport("."));
        }
    }
}
