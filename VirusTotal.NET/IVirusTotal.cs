using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using VirusTotalNET.Objects;

namespace VirusTotalNET
{
    public interface IVirusTotal
    {
        /// <summary>
        /// Set to true to use HTTPS instead of HTTP.
        /// </summary>
        bool UseTLS { get; set; }

        /// <summary>
        /// Get or set the proxy.
        /// </summary>
        IWebProxy Proxy { get; set; }

        /// <summary>
        /// The number of retries to attempt if an serialization error happens.
        /// </summary>
        int Retry { get; set; }

        /// <summary>
        /// Get or set the timeout.
        /// </summary>
        int Timeout { get; set; }

        /// <summary>
        /// Scan a file.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// </summary>
        /// <param name="file">The file to scan</param>
        /// <returns>The scan results.</returns>
        ScanResult ScanFile(FileInfo file);

        /// <summary>
        /// Scan a array of bytes.
        /// </summary>
        /// <param name="bytes">Array of bytes to be scanned</param>
        /// <param name="fileName">Filename that will be scanned</param>
        /// <returns>The scan results.</returns>
        ScanResult ScanFile(byte[] bytes, string fileName);

        /// <summary>
        /// Scan multiple files.
        /// Note: It is highly encouraged to get the report of the files before scanning, in case it they already been scanned before.
        /// </summary>
        /// <param name="files">The files you wish to scan.</param>
        /// <returns>The scan results.</returns>
        IEnumerable<ScanResult> ScanFiles(IEnumerable<FileInfo> files);

        /// <summary>
        /// Tell VirusTotal to rescan a file without sending the actual file to VirusTotal.
        /// Note: Before requesting a rescan you should retrieve the latest report on the file.
        /// </summary>
        /// <returns>The scan results.</returns>
        ScanResult RescanFile(FileInfo file);

        /// <summary>
        /// Tell VirusTotal to rescan a file without sending the actual file to VirusTotal.
        /// Note: Before requesting a rescan you should retrieve the latest report on the files.
        /// </summary>
        /// <returns>The scan results.</returns>
        List<ScanResult> RescanFiles(IEnumerable<FileInfo> files);

        /// <summary>
        /// Tell VirusTotal to rescan a file without sending the actual file to VirusTotal.
        /// Note: Before requesting a rescan you should retrieve the latest report on the files.
        /// </summary>
        /// <param name="resourceList">a MD5, SHA1 or SHA256 of the files. You can also specify list made up of a combination of any of the three allowed hashes (up to 25 items), this allows you to perform a batch request with one single call.
        /// Note: that the files must already be present in the files store.
        /// </param>
        /// <returns>The scan results.</returns>
        List<ScanResult> RescanFiles(IEnumerable<string> resourceList);

        /// <summary>
        /// Gets the report of the file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// </summary>
        /// <param name="file">The file you wish to get a report on.</param>
        Report GetFileReport(FileInfo file);

        /// <summary>
        /// Gets the report of the file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// </summary>
        /// <param name="resource">The resource (MD5, SHA1 or SHA256) you wish to get a report on.</param>
        Report GetFileReport(string resource);

        /// <summary>
        /// Gets a list of reports of the files.
        /// Note: This does not send the files to VirusTotal. It hashes the files and sends them instead.
        /// </summary>
        /// <param name="files">The files you wish to get reports on.</param>
        List<Report> GetFileReports(IEnumerable<FileInfo> files);

        /// <summary>
        /// Gets the report of the file represented by its hash or scan ID.
        /// Keep in mind that URLs sent using the API have the lowest scanning priority, depending on VirusTotal's load, it may take several hours before the file is scanned,
        /// so query the report at regular intervals until the result shows up and do not keep submitting the file over and over again.
        /// </summary>
        /// <param name="resourceList">SHA1, MD5 or SHA256 of the file. It can also be a scan ID of a previous scan.</param>
        /// <returns></returns>
        List<Report> GetFileReports(IEnumerable<string> resourceList);

        /// <summary>
        /// Scan the given URL. The URL will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest report on the URL.
        /// </summary>
        /// <param name="url">The url to process.</param>
        /// <returns>The scan results.</returns>
        ScanResult ScanUrl(string url);

        /// <summary>
        /// Scan the given URL. The URL will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest report on the URL.
        /// </summary>
        /// <param name="url">The url to process.</param>
        /// <returns>The scan results.</returns>
        ScanResult ScanUrl(Uri url);

        /// <summary>
        /// Scan the given URLs. The URLs will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest reports on the URLs.
        /// </summary>
        /// <param name="urlList">The urls to process.</param>
        /// <returns>The scan results.</returns>
        List<ScanResult> ScanUrls(IEnumerable<string> urlList);

        /// <summary>
        /// Scan the given URLs. The URLs will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest reports on the URLs.
        /// </summary>
        /// <param name="urlList">The urls to process.</param>
        /// <returns>The scan results.</returns>
        List<ScanResult> ScanUrls(IEnumerable<Uri> urlList);

        /// <summary>
        /// Gets a scan report from an URL
        /// </summary>
        /// <param name="url">The URL you wish to get the report on.</param>
        /// <returns>A list of reports</returns>
        Report GetUrlReport(string url);

        /// <summary>
        /// Gets a scan report from an URL
        /// </summary>
        /// <param name="url">The URL you wish to get the report on.</param>
        /// <returns>A list of reports</returns>
        Report GetUrlReport(Uri url);

        /// <summary>
        /// Gets a scan report from a list of URLs
        /// </summary>
        /// <param name="urlList">The URLs you wish to get the reports on.</param>
        /// <returns>A list of reports</returns>
        List<Report> GetUrlReports(IEnumerable<string> urlList);

        /// <summary>
        /// Gets a scan report from a list of URLs
        /// </summary>
        /// <param name="urlList">The URLs you wish to get the reports on.</param>
        /// <returns>A list of reports</returns>
        List<Report> GetUrlReports(IEnumerable<Uri> urlList);

        /// <summary>
        /// Creates a comment on a file denoted by its hash and/or scan ID.
        /// </summary>
        /// <param name="resource">The SHA256 hash or scan ID of the resource.</param>
        /// <param name="comment">The comment you wish to add.</param>
        /// <returns>A ScanResult object containing information about the resource.</returns>
        ScanResult CreateComment(string resource, string comment);

        /// <summary>
        /// Gives you a link to a file analysis based on its hash.
        /// </summary>
        /// <returns>A link to VirusTotal that contains the report</returns>
        string GetPublicFileScanLink(string resource);

        /// <summary>
        /// Gives you a link to a file analysis based on its hash.
        /// </summary>
        /// <returns>A link to VirusTotal that contains the report</returns>
        string GetPublicFileScanLink(FileInfo file);

        /// <summary>
        /// Gives you a link to a URL analysis.
        /// </summary>
        /// <returns>A link to VirusTotal that contains the report</returns>
        string GetPublicUrlScanLink(string url);
    }
}