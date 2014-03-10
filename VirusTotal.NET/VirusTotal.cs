using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.Serialization;
using System.Text.RegularExpressions;
using RestSharp;
using RestSharp.Deserializers;
using VirusTotalNET.Exceptions;
using VirusTotalNET.Objects;

namespace VirusTotalNET
{
    public partial class VirusTotal
    {
        private static readonly RestClient Client = new RestClient();
        private readonly string _apiKey;
        private bool _useTls;
        private const long FileSizeLimit = 33554432; //32 MB
        private int _retryCounter;
        private int _retry;

        /// <summary>
        /// Public constructor for VirusTotal.
        /// </summary>
        /// <param name="apiKey">The API key you got from Virus Total</param>
        /// <exception cref="ArgumentException"></exception>
        public VirusTotal(string apiKey)
        {
            if (string.IsNullOrEmpty(apiKey) || apiKey.Length < 64)
                throw new ArgumentException("You have to set an API key.", "apiKey");

            _apiKey = apiKey;
            Client.BaseUrl = "http://www.virustotal.com/vtapi/v2/";
            Client.FollowRedirects = false;

            Retry = 3;
        }

        /// <summary>
        /// Set to true to use HTTPS instead of HTTP.
        /// </summary>
        public bool UseTLS
        {
            get { return _useTls; }
            set
            {
                _useTls = value;
                Client.BaseUrl = value ? Client.BaseUrl.Replace("http://", "https://") : Client.BaseUrl.Replace("https://", "http://");
            }
        }

        /// <summary>
        /// Get or set the proxy.
        /// </summary>
        public IWebProxy Proxy { get { return Client.Proxy; } set { Client.Proxy = value; } }

        /// <summary>
        /// The number of retries to attempt if an serialization error happens.
        /// </summary>
        public int Retry
        {
            get { return _retry; }
            set
            {
                _retry = value;
                _retryCounter = value;
            }
        }

        /// <summary>
        /// Get or set the timeout.
        /// </summary>
        public int Timeout { get { return Client.Timeout; } set { Client.Timeout = value; } }

        /// <summary>
        /// Scan a file.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// </summary>
        /// <param name="file">The file to scan</param>
        /// <returns>The scan results.</returns>
        public ScanResult ScanFile(FileInfo file)
        {
            if (!file.Exists)
                throw new FileNotFoundException("The file was not found.", file.Name);

            //https://www.virustotal.com/vtapi/v2/file/scan
            RestRequest request = new RestRequest("file/scan", Method.POST);

            //Required
            request.AddParameter("apikey", _apiKey);

            if (file.Length <= FileSizeLimit)
                request.AddFile("file", file.FullName);
            else
                throw new SizeLimitException("The filesize limit on VirusTotal is 32 MB. Your file is " + file.Length / 1024 / 1024 + " MB");

            //Output
            return GetResults<ScanResult>(request);
        }

        /// <summary>
        /// Scan multiple files.
        /// Note: It is highly encouraged to get the report of the files before scanning, in case it they already been scanned before.
        /// </summary>
        /// <param name="files">The files you wish to scan.</param>
        /// <returns>The scan results.</returns>
        public IEnumerable<ScanResult> ScanFiles(IEnumerable<FileInfo> files)
        {
            foreach (FileInfo fileInfo in files)
            {
                yield return ScanFile(fileInfo);
            }
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file without sending the actual file to VirusTotal.
        /// Note: Before requesting a rescan you should retrieve the latest report on the file.
        /// </summary>
        /// <returns>The scan results.</returns>
        public ScanResult RescanFile(FileInfo file)
        {
            return RescanFiles(new[] { file }).First();
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file without sending the actual file to VirusTotal.
        /// Note: Before requesting a rescan you should retrieve the latest report on the files.
        /// </summary>
        /// <returns>The scan results.</returns>
        public List<ScanResult> RescanFiles(IEnumerable<FileInfo> files)
        {
            IEnumerable<string> hashes = GetResourcesFromFiles(files);
            return RescanFiles(hashes);
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file without sending the actual file to VirusTotal.
        /// Note: Before requesting a rescan you should retrieve the latest report on the files.
        /// </summary>
        /// <param name="resourceList">a MD5, SHA1 or SHA256 of the files. You can also specify list made up of a combination of any of the three allowed hashes (up to 25 items), this allows you to perform a batch request with one single call.
        /// Note: that the files must already be present in the files store.
        /// </param>
        /// <returns>The scan results.</returns>
        public List<ScanResult> RescanFiles(IEnumerable<string> resourceList)
        {
            string[] hashes = resourceList as string[] ?? resourceList.ToArray();

            if (!hashes.Any())
                throw new Exception("You have to supply a resource.");

            for (int i = 0; i < hashes.Length; i++)
            {
                ValidateResource(hashes[i]);
            }

            //https://www.virustotal.com/vtapi/v2/file/rescan
            RestRequest request = new RestRequest("file/rescan", Method.POST);

            //Required
            request.AddParameter("apikey", _apiKey);
            request.AddParameter("resource", string.Join(",", hashes));

            //Output
            return GetResults<List<ScanResult>>(request);
        }

        /// <summary>
        /// Gets the report of the file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// </summary>
        /// <param name="file">The file you wish to get a report on.</param>
        public Report GetFileReport(FileInfo file)
        {
            return GetFileReport(HashHelper.GetSHA256(file));
        }

        /// <summary>
        /// Gets the report of the file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// </summary>
        /// <param name="resource">The resource (MD5, SHA1 or SHA256) you wish to get a report on.</param>
        public Report GetFileReport(string resource)
        {
            return GetFileReports(new[] { resource }).First();
        }

        /// <summary>
        /// Gets a list of reports of the files.
        /// Note: This does not send the files to VirusTotal. It hashes the files and sends them instead.
        /// </summary>
        /// <param name="files">The files you wish to get reports on.</param>
        public List<Report> GetFileReports(IEnumerable<FileInfo> files)
        {
            IEnumerable<string> hashes = GetResourcesFromFiles(files);
            return GetFileReports(hashes);
        }

        /// <summary>
        /// Gets the report of the file represented by its hash or scan ID.
        /// Keep in mind that URLs sent using the API have the lowest scanning priority, depending on VirusTotal's load, it may take several hours before the file is scanned,
        /// so query the report at regular intervals until the result shows up and do not keep submitting the file over and over again.
        /// </summary>
        /// <param name="resourceList">SHA1, MD5 or SHA256 of the file. It can also be a scan ID of a previous scan.</param>
        /// <returns></returns>
        public List<Report> GetFileReports(IEnumerable<string> resourceList)
        {
            string[] hashes = resourceList as string[] ?? resourceList.ToArray();

            if (!hashes.Any())
                throw new ArgumentException("You have to supply a resource.");

            for (int i = 0; i < hashes.Length; i++)
            {
                ValidateResource(hashes[i]);
            }

            //https://www.virustotal.com/vtapi/v2/file/report
            RestRequest request = new RestRequest("file/report", Method.POST);

            //Required
            request.AddParameter("apikey", _apiKey);
            request.AddParameter("resource", string.Join(",", hashes));

            //Output
            return GetResults<List<Report>>(request, true);
        }

        /// <summary>
        /// Scan the given URL. The URL will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest report on the URL.
        /// </summary>
        /// <param name="url">The url to process.</param>
        /// <returns>The scan results.</returns>
        public ScanResult ScanUrl(string url)
        {
            return ScanUrl(new Uri(url));
        }

        /// <summary>
        /// Scan the given URL. The URL will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest report on the URL.
        /// </summary>
        /// <param name="url">The url to process.</param>
        /// <returns>The scan results.</returns>
        public ScanResult ScanUrl(Uri url)
        {
            return ScanUrls(new[] { url }).First();
        }

        /// <summary>
        /// Scan the given URLs. The URLs will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest reports on the URLs.
        /// </summary>
        /// <param name="urlList">The urls to process.</param>
        /// <returns>The scan results.</returns>
        public List<ScanResult> ScanUrls(IEnumerable<string> urlList)
        {
            IEnumerable<Uri> uris = UrlToUri(urlList);
            return ScanUrls(uris);
        }

        /// <summary>
        /// Scan the given URLs. The URLs will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest reports on the URLs.
        /// </summary>
        /// <param name="urlList">The urls to process.</param>
        /// <returns>The scan results.</returns>
        public List<ScanResult> ScanUrls(IEnumerable<Uri> urlList)
        {
            IEnumerable<Uri> urls = urlList as Uri[] ?? urlList.ToArray();

            if (!urls.Any())
                throw new Exception("You have to supply an URL.");

            //https://www.virustotal.com/vtapi/v2/url/scan
            RestRequest request = new RestRequest("url/scan", Method.POST);

            //Required
            request.AddParameter("apikey", _apiKey);
            request.AddParameter("url", string.Join(",", urls));

            //Output
            return GetResults<List<ScanResult>>(request);
        }

        /// <summary>
        /// Gets a scan report from an URL
        /// </summary>
        /// <param name="url">The URL you wish to get the report on.</param>
        /// <returns>A list of reports</returns>
        public Report GetUrlReport(string url)
        {
            return GetUrlReport(new Uri(url));
        }

        /// <summary>
        /// Gets a scan report from an URL
        /// </summary>
        /// <param name="url">The URL you wish to get the report on.</param>
        /// <returns>A list of reports</returns>
        public Report GetUrlReport(Uri url)
        {
            return GetUrlReports(new[] { url }).First();
        }

        /// <summary>
        /// Gets a scan report from a list of URLs
        /// </summary>
        /// <param name="urlList">The URLs you wish to get the reports on.</param>
        /// <returns>A list of reports</returns>
        public List<Report> GetUrlReports(IEnumerable<string> urlList)
        {
            IEnumerable<Uri> uris = UrlToUri(urlList);
            return GetUrlReports(uris);
        }

        /// <summary>
        /// Gets a scan report from a list of URLs
        /// </summary>
        /// <param name="urlList">The URLs you wish to get the reports on.</param>
        /// <returns>A list of reports</returns>
        public List<Report> GetUrlReports(IEnumerable<Uri> urlList)
        {
            IEnumerable<Uri> urls = urlList as Uri[] ?? urlList.ToArray();

            if (!urls.Any())
                throw new Exception("You have to supply an URL.");

            RestRequest request = new RestRequest("url/report", Method.POST);

            //Required
            request.AddParameter("apikey", _apiKey);
            request.AddParameter("resource", string.Join(",", urls));

            //Output
            return GetResults<List<Report>>(request, true);
        }

        /// <summary>
        /// Creates a comment on a file denoted by its hash and/or scan ID.
        /// </summary>
        /// <param name="resource">The SHA256 hash or scan ID of the resource.</param>
        /// <param name="comment">The comment you wish to add.</param>
        /// <returns>A ScanResult object containing information about the resource.</returns>
        public ScanResult CreateComment(string resource, string comment)
        {
            ValidateResource(resource);

            if (string.IsNullOrWhiteSpace(comment))
                throw new ArgumentException("Comment must not be null or whitespace", "comment");

            //https://www.virustotal.com/vtapi/v2/comments/put
            RestRequest request = new RestRequest("comments/put", Method.POST);

            //Required
            request.AddParameter("apikey", _apiKey);
            request.AddParameter("resource", resource);
            request.AddParameter("comment", comment);

            //Output
            return GetResults<ScanResult>(request);
        }

        /// <summary>
        /// Gives you a link to a file analysis based on its hash.
        /// </summary>
        /// <returns>A link to VirusTotal that contains the report</returns>
        public string GetPublicFileScanLink(string resource)
        {
            ValidateResource(resource);

            return string.Format("{0}://www.virustotal.com/file/{1}/analysis/", UseTLS ? "https" : "http", resource);
        }

        /// <summary>
        /// Gives you a link to a file analysis based on its hash.
        /// </summary>
        /// <returns>A link to VirusTotal that contains the report</returns>
        public string GetPublicFileScanLink(FileInfo file)
        {
            return GetPublicFileScanLink(HashHelper.GetSHA256(file));
        }

        /// <summary>
        /// Gives you a link to a URL analysis.
        /// </summary>
        /// <returns>A link to VirusTotal that contains the report</returns>
        public string GetPublicUrlScanLink(string url)
        {
            return string.Format("{0}://www.virustotal.com/url/{1}/analysis/", UseTLS ? "https" : "http", HashHelper.GetSHA256(NormalizeUrl(url)));
        }

        private T GetResults<T>(RestRequest request, bool applyHack = false)
        {
            RestResponse response = (RestResponse)Client.Execute(request);

            if (response.StatusCode == HttpStatusCode.NoContent)
                throw new RateLimitException("You have reached the 5 requests pr. min. limit of VirusTotal");

            if (response.StatusCode == HttpStatusCode.Forbidden)
                throw new AccessDeniedException("You don't have access to the service. Make sure your API key is working correctly.");

            if (applyHack)
            {
                //Warning: Huge hack... sorry :(
                response.Content = Regex.Replace(response.Content, "\"([\\w\\d -\\._]+)\": \\{\"detected\":", "{\"name\": \"$1\", \"detected\":", RegexOptions.Compiled | RegexOptions.CultureInvariant);
                response.Content = response.Content.Replace("scans\": {", "scans\": [");
                response.Content = response.Content.Replace("}}", "}]");
            }

            IDeserializer deserializer = new JsonDeserializer();
            T results;

            try
            {
                results = deserializer.Deserialize<T>(response);
            }
            catch (SerializationException)
            {
                //retry request.
                try
                {
                    _retryCounter--;

                    if (_retryCounter <= 0)
                    {
                        _retryCounter = Retry;
                        return default(T);
                    }
                    results = GetResults<T>(request, applyHack);
                }
                catch (SerializationException ex)
                {
                    throw new Exception("Failed to deserialize request.", ex);
                }
            }

            //reset retry counter
            _retryCounter = Retry;
            return results;
        }

        private string NormalizeUrl(string url)
        {
            if (!url.StartsWith("http://") && !url.StartsWith("https://"))
                url = "http://" + url;

            Uri uri = new Uri(url);
            return uri.ToString();
        }

        private IEnumerable<string> GetResourcesFromFiles(IEnumerable<FileInfo> files)
        {
            foreach (FileInfo fileInfo in files)
            {
                if (!fileInfo.Exists)
                    throw new FileNotFoundException("The file " + fileInfo.FullName + " does not exist.");

                yield return HashHelper.GetSHA256(fileInfo);
            }
        }

        private IEnumerable<Uri> UrlToUri(IEnumerable<string> urls)
        {
            foreach (string url in urls)
            {
                yield return new Uri(url);
            }
        }

        private void ValidateResource(string resource)
        {
            if (string.IsNullOrWhiteSpace(resource))
                throw new ArgumentException("Resource must not be null or whitespace", "resource");

            if (resource.Length != 32 && resource.Length != 40 && resource.Length != 64)
                throw new InvalidResourceException("Resource " + resource + " has to be either a MD5, SHA1 or SHA256");
        }
    }
}