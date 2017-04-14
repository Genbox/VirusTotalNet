using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using VirusTotalNET.Exceptions;
using VirusTotalNET.Results;
using VirusTotalNET.UnitTests.TestInternals;
using Xunit;

namespace VirusTotalNET.UnitTests
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
            IgnoreMissingJson("[array].scans.Ad-Aware / Detail", "[array].scans.AegisLab / Detail", "[array].scans.AhnLab-V3 / Detail", "[array].scans.ALYac / Detail", "[array].scans.Antiy-AVL / Detail", "[array].scans.Arcabit / Detail", "[array].scans.Avast / Detail", "[array].scans.AVG / Detail", "[array].scans.Avira / Detail", "[array].scans.AVware / Detail", "[array].scans.Baidu / Detail", "[array].scans.BitDefender / Detail", "[array].scans.Bkav / Detail", "[array].scans.CAT-QuickHeal / Detail", "[array].scans.ClamAV / Detail", "[array].scans.CMC / Detail", "[array].scans.Comodo / Detail", "[array].scans.Cyren / Detail", "[array].scans.DrWeb / Detail", "[array].scans.Emsisoft / Detail", "[array].scans.Endgame / Detail", "[array].scans.ESET-NOD32 / Detail", "[array].scans.Fortinet / Detail", "[array].scans.F-Prot / Detail", "[array].scans.F-Secure / Detail", "[array].scans.GData / Detail", "[array].scans.Ikarus / Detail", "[array].scans.Jiangmin / Detail", "[array].scans.K7AntiVirus / Detail", "[array].scans.K7GW / Detail", "[array].scans.Kaspersky / Detail", "[array].scans.Kingsoft / Detail", "[array].scans.Malwarebytes / Detail", "[array].scans.McAfee / Detail", "[array].scans.McAfee-GW-Edition / Detail", "[array].scans.Microsoft / Detail", "[array].scans.MicroWorld-eScan / Detail", "[array].scans.NANO-Antivirus / Detail", "[array].scans.nProtect / Detail", "[array].scans.Panda / Detail", "[array].scans.Qihoo-360 / Detail", "[array].scans.Rising / Detail", "[array].scans.Sophos / Detail", "[array].scans.SUPERAntiSpyware / Detail", "[array].scans.Symantec / Detail", "[array].scans.Tencent / Detail", "[array].scans.TheHacker / Detail", "[array].scans.TotalDefense / Detail", "[array].scans.TrendMicro / Detail", "[array].scans.TrendMicro-HouseCall / Detail", "[array].scans.VBA32 / Detail", "[array].scans.VIPRE / Detail", "[array].scans.ViRobot / Detail", "[array].scans.Webroot / Detail", "[array].scans.Yandex / Detail", "[array].scans.Zillya / Detail", "[array].scans.ZoneAlarm / Detail", "[array].scans.Zoner / Detail");

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
            IgnoreMissingJson("[array].scans.ADMINUSLabs / Detail", "[array].scans.ADMINUSLabs / Update", "[array].scans.ADMINUSLabs / Version", "[array].scans.AlienVault / Detail", "[array].scans.AlienVault / Update", "[array].scans.AlienVault / Version", "[array].scans.Antiy-AVL / Detail", "[array].scans.Antiy-AVL / Update", "[array].scans.Antiy-AVL / Version", "[array].scans.AutoShun / Detail", "[array].scans.AutoShun / Update", "[array].scans.AutoShun / Version", "[array].scans.Avira / Detail", "[array].scans.Avira / Update", "[array].scans.Avira / Version", "[array].scans.Baidu-International / Detail", "[array].scans.Baidu-International / Update", "[array].scans.Baidu-International / Version", "[array].scans.BitDefender / Detail", "[array].scans.BitDefender / Update", "[array].scans.BitDefender / Version", "[array].scans.Blueliv / Detail", "[array].scans.Blueliv / Update", "[array].scans.Blueliv / Version", "[array].scans.Certly / Detail", "[array].scans.Certly / Update", "[array].scans.Certly / Version", "[array].scans.C-SIRT / Detail", "[array].scans.C-SIRT / Update", "[array].scans.C-SIRT / Version", "[array].scans.CyberCrime / Detail", "[array].scans.CyberCrime / Update", "[array].scans.CyberCrime / Version", "[array].scans.Emsisoft / Detail", "[array].scans.Emsisoft / Update", "[array].scans.Emsisoft / Version", "[array].scans.ESET / Detail", "[array].scans.ESET / Update", "[array].scans.ESET / Version", "[array].scans.Fortinet / Detail", "[array].scans.Fortinet / Update", "[array].scans.Fortinet / Version", "[array].scans.FraudScore / Detail", "[array].scans.FraudScore / Update", "[array].scans.FraudScore / Version", "[array].scans.FraudSense / Detail", "[array].scans.FraudSense / Update", "[array].scans.FraudSense / Version", "[array].scans.G-Data / Detail", "[array].scans.G-Data / Update", "[array].scans.G-Data / Version", "[array].scans.K7AntiVirus / Detail", "[array].scans.K7AntiVirus / Update", "[array].scans.K7AntiVirus / Version", "[array].scans.Kaspersky / Detail", "[array].scans.Kaspersky / Update", "[array].scans.Kaspersky / Version", "[array].scans.Malekal / Detail", "[array].scans.Malekal / Update", "[array].scans.Malekal / Version", "[array].scans.Malwared / Detail", "[array].scans.Malwared / Update", "[array].scans.Malwared / Version", "[array].scans.MalwareDomainList / Update", "[array].scans.MalwareDomainList / Version", "[array].scans.MalwarePatrol / Detail", "[array].scans.MalwarePatrol / Update", "[array].scans.MalwarePatrol / Version", "[array].scans.Netcraft / Detail", "[array].scans.Netcraft / Update", "[array].scans.Netcraft / Version", "[array].scans.Nucleon / Detail", "[array].scans.Nucleon / Update", "[array].scans.Nucleon / Version", "[array].scans.OpenPhish / Detail", "[array].scans.OpenPhish / Update", "[array].scans.OpenPhish / Version", "[array].scans.Opera / Detail", "[array].scans.Opera / Update", "[array].scans.Opera / Version", "[array].scans.ParetoLogic / Detail", "[array].scans.ParetoLogic / Update", "[array].scans.ParetoLogic / Version", "[array].scans.PhishLabs / Detail", "[array].scans.PhishLabs / Update", "[array].scans.PhishLabs / Version", "[array].scans.Phishtank / Detail", "[array].scans.Phishtank / Update", "[array].scans.Phishtank / Version", "[array].scans.Quttera / Detail", "[array].scans.Quttera / Update", "[array].scans.Quttera / Version", "[array].scans.Rising / Detail", "[array].scans.Rising / Update", "[array].scans.Rising / Version", "[array].scans.SecureBrain / Detail", "[array].scans.SecureBrain / Update", "[array].scans.SecureBrain / Version", "[array].scans.securolytics / Detail", "[array].scans.securolytics / Update", "[array].scans.securolytics / Version", "[array].scans.Sophos / Detail", "[array].scans.Sophos / Update", "[array].scans.Sophos / Version", "[array].scans.Spam404 / Detail", "[array].scans.Spam404 / Update", "[array].scans.Spam404 / Version", "[array].scans.StopBadware / Detail", "[array].scans.StopBadware / Update", "[array].scans.StopBadware / Version", "[array].scans.Tencent / Detail", "[array].scans.Tencent / Update", "[array].scans.Tencent / Version", "[array].scans.ThreatHive / Detail", "[array].scans.ThreatHive / Update", "[array].scans.ThreatHive / Version", "[array].scans.Trustwave / Detail", "[array].scans.Trustwave / Update", "[array].scans.Trustwave / Version", "[array].scans.URLQuery / Detail", "[array].scans.URLQuery / Update", "[array].scans.URLQuery / Version", "[array].scans.Webutation / Detail", "[array].scans.Webutation / Update", "[array].scans.Webutation / Version", "[array].scans.ZCloudsec / Detail", "[array].scans.ZCloudsec / Update", "[array].scans.ZCloudsec / Version", "[array].scans.ZeroCERT / Detail", "[array].scans.ZeroCERT / Update", "[array].scans.ZeroCERT / Version", "[array].scans.Zerofox / Detail", "[array].scans.Zerofox / Update", "[array].scans.Zerofox / Version", "[array].scans.ZeusTracker / Update", "[array].scans.ZeusTracker / Version", "[array].scans.zvelo / Detail", "[array].scans.zvelo / Update", "[array].scans.zvelo / Version", "[array].scans['AegisLab WebGuard'] / Detail", "[array].scans['AegisLab WebGuard'] / Update", "[array].scans['AegisLab WebGuard'] / Version", "[array].scans['CLEAN MX'] / Detail", "[array].scans['CLEAN MX'] / Update", "[array].scans['CLEAN MX'] / Version", "[array].scans['Comodo Site Inspector'] / Detail", "[array].scans['Comodo Site Inspector'] / Update", "[array].scans['Comodo Site Inspector'] / Version", "[array].scans['desenmascara.me'] / Detail", "[array].scans['desenmascara.me'] / Update", "[array].scans['desenmascara.me'] / Version", "[array].scans['Dr.Web'] / Detail", "[array].scans['Dr.Web'] / Update", "[array].scans['Dr.Web'] / Version", "[array].scans['Google Safebrowsing'] / Detail", "[array].scans['Google Safebrowsing'] / Update", "[array].scans['Google Safebrowsing'] / Version", "[array].scans['Malc0de Database'] / Update", "[array].scans['Malc0de Database'] / Version", "[array].scans['Malware Domain Blocklist'] / Detail", "[array].scans['Malware Domain Blocklist'] / Update", "[array].scans['Malware Domain Blocklist'] / Version", "[array].scans['Malwarebytes hpHosts'] / Detail", "[array].scans['Malwarebytes hpHosts'] / Update", "[array].scans['Malwarebytes hpHosts'] / Version", "[array].scans['malwares.com URL checker'] / Detail", "[array].scans['malwares.com URL checker'] / Update", "[array].scans['malwares.com URL checker'] / Version", "[array].scans['SCUMWARE.org'] / Detail", "[array].scans['SCUMWARE.org'] / Update", "[array].scans['SCUMWARE.org'] / Version", "[array].scans['Sucuri SiteCheck'] / Detail", "[array].scans['Sucuri SiteCheck'] / Update", "[array].scans['Sucuri SiteCheck'] / Version", "[array].scans['VX Vault'] / Detail", "[array].scans['VX Vault'] / Update", "[array].scans['VX Vault'] / Version", "[array].scans['Web Security Guard'] / Detail", "[array].scans['Web Security Guard'] / Update", "[array].scans['Web Security Guard'] / Version", "[array].scans['Websense ThreatSeeker'] / Detail", "[array].scans['Websense ThreatSeeker'] / Update", "[array].scans['Websense ThreatSeeker'] / Version", "[array].scans['Yandex Safebrowsing'] / Update", "[array].scans['Yandex Safebrowsing'] / Version", "[array].scans['ZDB Zeus'] / Detail", "[array].scans['ZDB Zeus'] / Update", "[array].scans['ZDB Zeus'] / Version");

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
            IgnoreMissingJson(" / Alexa category", " / Alexa domain info", " / Alexa rank", " / BitDefender category", " / BitDefender domain info", " / detected_communicating_samples", " / detected_downloaded_samples", " / detected_referrer_samples", " / Dr.Web category", " / Opera domain info", " / Pcaps", " / subdomains", " / TrendMicro category", " / undetected_communicating_samples", " / undetected_downloaded_samples", " / undetected_referrer_samples", " / WOT domain info", "detected_referrer_samples[array] / Date", "resolutions[array] / Hostname", "undetected_referrer_samples[array] / Date");

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
