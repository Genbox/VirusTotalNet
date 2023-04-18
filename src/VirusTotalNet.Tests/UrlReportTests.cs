using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using VirusTotalNet.Exceptions;
using VirusTotalNet.ResponseCodes;
using VirusTotalNet.Results;
using VirusTotalNet.Tests.TestInternals;
using Xunit;

namespace VirusTotalNet.Tests;

public class UrlReportTests : TestBase
{
    [Fact]
    public async Task GetReportKnownUrl()
    {
        IgnoreMissingJson("scans.0xSI_f33d / Detail", "scans.Abusix / Detail", "scans.Acronis / Detail", "scans.ADMINUSLabs / Detail", "scans.AlienVault / Detail", "scans.AlphaSOC / Detail", "scans.Antiy-AVL / Detail", "scans.AutoShun / Detail", "scans.Avira / Detail", "scans.BitDefender / Detail", "scans.Bkav / Detail", "scans.BlockList / Detail", "scans.Blueliv / Detail", "scans.Certego / Detail", "scans.Cluster25 / Detail", "scans.CRDF / Detail", "scans.CrowdSec / Detail", "scans.Cyan / Detail", "scans.Cyble / Detail", "scans.CyRadar / Detail", "scans.DNS8 / Detail", "scans.EmergingThreats / Detail", "scans.Emsisoft / Detail", "scans.ESET / Detail", "scans.ESTsecurity / Detail", "scans.Fortinet / Detail", "scans.G-Data / Detail", "scans.GreenSnow / Detail", "scans.IPsum / Detail", "scans.K7AntiVirus / Detail", "scans.Kaspersky / Detail", "scans.Lionic / Detail", "scans.Lumu / Detail", "scans.Malwared / Detail", "scans.MalwarePatrol / Detail", "scans.Netcraft / Detail", "scans.OpenPhish / Detail", "scans.PhishFort / Detail", "scans.PhishLabs / Detail", "scans.Phishtank / Detail", "scans.PREBYTES / Detail", "scans.PrecisionSec / Detail", "scans.Quttera / Detail", "scans.Rising / Detail", "scans.SafeToOpen / Detail", "scans.Sangfor / Detail", "scans.Scantitan / Detail", "scans.Seclookup / Detail", "scans.SecureBrain / Detail", "scans.securolytics / Detail", "scans.Sophos / Detail", "scans.Spam404 / Detail", "scans.StopForumSpam / Detail", "scans.ThreatHive / Detail", "scans.Threatsourcing / Detail", "scans.Trustwave / Detail", "scans.URLhaus / Detail", "scans.URLQuery / Detail", "scans.VIPRE / Detail", "scans.ViriBack / Detail", "scans.Webroot / Detail", "scans.ZeroCERT / Detail", "scans['AICC (MONITORAPP)'] / Detail", "scans['alphaMountain.ai'] / Detail", "scans['ArcSight Threat Intelligence'] / Detail", "scans['Artists Against 419'] / Detail", "scans['benkow.cc'] / Detail", "scans['Bfore.Ai PreCrime'] / Detail", "scans['Chong Lua Dao'] / Detail", "scans['CINS Army'] / Detail", "scans['CMC Threat Intelligence'] / Detail", "scans['Criminal IP'] / Detail", "scans['desenmascara.me'] / Detail", "scans['Dr.Web'] / Detail", "scans['Feodo Tracker'] / Detail", "scans['Forcepoint ThreatSeeker'] / Detail", "scans['Google Safebrowsing'] / Detail", "scans['Heimdal Security'] / Detail", "scans['Juniper Networks'] / Detail", "scans['malwares.com URL checker'] / Detail", "scans['Phishing Database'] / Detail", "scans['Quick Heal'] / Detail", "scans['SCUMWARE.org'] / Detail", "scans['Snort IP sample list'] / Detail", "scans['Sucuri SiteCheck'] / Detail", "scans['Viettel Threat Intelligence'] / Detail", "scans['VX Vault'] / Detail", "scans['Xcitium Verdict Cloud'] / Detail");
        UrlReport urlReport = await VirusTotal.GetUrlReportAsync(TestData.KnownUrls.First());
        Assert.Equal(UrlReportResponseCode.Present, urlReport.ResponseCode);
    }

    [Fact]
    public async Task GetMultipleReportKnownUrl()
    {
        IgnoreMissingJson("[array].scans.0xSI_f33d / Detail", "[array].scans.Abusix / Detail", "[array].scans.Acronis / Detail", "[array].scans.ADMINUSLabs / Detail", "[array].scans.AlienVault / Detail", "[array].scans.AlphaSOC / Detail", "[array].scans.Antiy-AVL / Detail", "[array].scans.AutoShun / Detail", "[array].scans.Avira / Detail", "[array].scans.BitDefender / Detail", "[array].scans.Bkav / Detail", "[array].scans.BlockList / Detail", "[array].scans.Blueliv / Detail", "[array].scans.Certego / Detail", "[array].scans.Cluster25 / Detail", "[array].scans.CRDF / Detail", "[array].scans.CrowdSec / Detail", "[array].scans.Cyan / Detail", "[array].scans.Cyble / Detail", "[array].scans.CyRadar / Detail", "[array].scans.DNS8 / Detail", "[array].scans.EmergingThreats / Detail", "[array].scans.Emsisoft / Detail", "[array].scans.ESET / Detail", "[array].scans.ESTsecurity / Detail", "[array].scans.Fortinet / Detail", "[array].scans.G-Data / Detail", "[array].scans.GreenSnow / Detail", "[array].scans.IPsum / Detail", "[array].scans.K7AntiVirus / Detail", "[array].scans.Kaspersky / Detail", "[array].scans.Lionic / Detail", "[array].scans.Lumu / Detail", "[array].scans.Malwared / Detail", "[array].scans.MalwarePatrol / Detail", "[array].scans.Netcraft / Detail", "[array].scans.OpenPhish / Detail", "[array].scans.PhishFort / Detail", "[array].scans.PhishLabs / Detail", "[array].scans.Phishtank / Detail", "[array].scans.PREBYTES / Detail", "[array].scans.PrecisionSec / Detail", "[array].scans.Quttera / Detail", "[array].scans.Rising / Detail", "[array].scans.SafeToOpen / Detail", "[array].scans.Sangfor / Detail", "[array].scans.Scantitan / Detail", "[array].scans.Seclookup / Detail", "[array].scans.SecureBrain / Detail", "[array].scans.securolytics / Detail", "[array].scans.Sophos / Detail", "[array].scans.Spam404 / Detail", "[array].scans.StopForumSpam / Detail", "[array].scans.ThreatHive / Detail", "[array].scans.Threatsourcing / Detail", "[array].scans.Trustwave / Detail", "[array].scans.URLhaus / Detail", "[array].scans.URLQuery / Detail", "[array].scans.VIPRE / Detail", "[array].scans.ViriBack / Detail", "[array].scans.Webroot / Detail", "[array].scans.ZeroCERT / Detail", "[array].scans['AICC (MONITORAPP)'] / Detail", "[array].scans['alphaMountain.ai'] / Detail", "[array].scans['ArcSight Threat Intelligence'] / Detail", "[array].scans['Artists Against 419'] / Detail", "[array].scans['benkow.cc'] / Detail", "[array].scans['Bfore.Ai PreCrime'] / Detail", "[array].scans['Chong Lua Dao'] / Detail", "[array].scans['CINS Army'] / Detail", "[array].scans['CMC Threat Intelligence'] / Detail", "[array].scans['Criminal IP'] / Detail", "[array].scans['desenmascara.me'] / Detail", "[array].scans['Dr.Web'] / Detail", "[array].scans['Feodo Tracker'] / Detail", "[array].scans['Forcepoint ThreatSeeker'] / Detail", "[array].scans['Google Safebrowsing'] / Detail", "[array].scans['Heimdal Security'] / Detail", "[array].scans['Juniper Networks'] / Detail", "[array].scans['malwares.com URL checker'] / Detail", "[array].scans['Phishing Database'] / Detail", "[array].scans['Quick Heal'] / Detail", "[array].scans['SCUMWARE.org'] / Detail", "[array].scans['Snort IP sample list'] / Detail", "[array].scans['Sucuri SiteCheck'] / Detail", "[array].scans['Viettel Threat Intelligence'] / Detail", "[array].scans['VX Vault'] / Detail", "[array].scans['Xcitium Verdict Cloud'] / Detail");

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