using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
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
        private readonly RestClient _client = new RestClient();
        private readonly string _apiKey;
        private bool _useTls;
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

            ApiUrl = "www.virustotal.com/vtapi/v2/";
            _useTls = true;
            _apiKey = apiKey;
            _client.FollowRedirects = false;

            Retry = 3;
            FileSizeLimit = 33553369; //32 MB - 1063 = 33553369 it is the effective limit by virus total
            RestrictSizeLimits = true;
            RestrictNumberOfResources = true;
        }

        /// <summary>
        /// When true, we check the file size before uploading it to Virus Total. The file size restrictions are based on the Virusl Total public API 2.0 documentation.
        /// </summary>
        public bool RestrictSizeLimits { get; set; }

        /// <summary>
        /// When true, we check the number of resources that are submitted to Virus Total. The limits are according to Virus Total public API 2.0 documentation.
        /// </summary>
        public bool RestrictNumberOfResources { get; set; }

        /// <summary>
        /// The maximum file size (in bytes) that the Virus Total public API 2.0 supports.
        /// </summary>
        public long FileSizeLimit { get; set; }

        /// <summary>
        /// Set to false to use HTTP instead of HTTPS. HTTPS is used by default.
        /// </summary>
        public bool UseTLS
        {
            get { return _useTls; }
            set
            {
                _useTls = value;

                string oldUrl = ApiUrl;

                if (string.IsNullOrWhiteSpace(oldUrl))
                    return;

                if (oldUrl.StartsWith("https://", StringComparison.InvariantCultureIgnoreCase))
                    oldUrl = oldUrl.Substring(8);
                else if (oldUrl.StartsWith("http://", StringComparison.InvariantCultureIgnoreCase))
                    oldUrl = oldUrl.Substring(7);

                _client.BaseUrl = _useTls ? new Uri("https://" + oldUrl) : new Uri("http://" + oldUrl);
            }
        }

        /// <summary>
        /// Get or set the proxy.
        /// </summary>
        public IWebProxy Proxy { get { return _client.Proxy; } set { _client.Proxy = value; } }

        /// <summary>
        /// The number of retries to attempt if an serialization error happens.
        /// It is set to 3 by default.
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
        /// Get or set the timeout in miliseconds.
        /// </summary>
        public int Timeout { get { return _client.Timeout; } set { _client.Timeout = value; } }

        /// <summary>
        /// The URL which the Virus Total service listens on. IF you don't set the scheme to http:// or https:// it will default to https.
        /// </summary>
        public string ApiUrl
        {
            get { return _client.BaseUrl.ToString(); }
            set
            {
                string newUrl = value.Trim();

                if (string.IsNullOrWhiteSpace(newUrl))
                    return;

                if (newUrl.StartsWith("https://", StringComparison.InvariantCultureIgnoreCase))
                {
                    _useTls = true;
                    newUrl = newUrl.Substring(8);
                }
                else if (newUrl.StartsWith("http://", StringComparison.InvariantCultureIgnoreCase))
                {
                    _useTls = false;
                    newUrl = newUrl.Substring(7);
                }
                else
                    _useTls = true;

                _client.BaseUrl = _useTls ? new Uri("https://" + newUrl) : new Uri("http://" + newUrl);
            }
        }

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

            using (FileStream stream = file.OpenRead())
                return ScanFile(stream, file.Name);
        }

        /// <summary>
        /// Scan a file.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// Note: Ýou are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
        /// </summary>
        /// <param name="file">The file to scan</param>
        /// <param name="filename">The filename of the file</param>
        /// <returns>The scan results.</returns>
        public ScanResult ScanFile(byte[] file, string filename)
        {
            using (MemoryStream stream = new MemoryStream(file))
                return ScanFile(stream, filename);
        }

        /// <summary>
        /// Scan a file.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// Note: Ýou are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
        /// </summary>
        /// <param name="fileStream">The file to scan</param>
        /// <param name="filename">The filename of the file</param>
        /// <returns>The scan results.</returns>
        public ScanResult ScanFile(Stream fileStream, string filename)
        {
            if (fileStream == null || fileStream.Length <= 0)
                throw new ArgumentException("You must provide a file", "fileStream");

            if (RestrictSizeLimits && fileStream.Length > FileSizeLimit)
                throw new SizeLimitException(string.Format("The filesize limit on VirusTotal is {0} KB. Your file is {1} KB", FileSizeLimit / 1024, fileStream.Length / 1024));

            if (string.IsNullOrWhiteSpace(filename))
                throw new ArgumentException("You must provide a filename. Preferably the original filename.");

            //https://www.virustotal.com/vtapi/v2/file/scan
            RestRequest request = PrepareRequest("file/scan");
            request.AddFile("file", fileStream.CopyTo, filename);

            //Output
            return GetResults<ScanResult>(request);
        }

        /// <summary>
        /// Scan multiple files.
        /// Note: It is highly encouraged to get the report of the files before scanning, in case it they already been scanned before.
        /// Note: Ýou are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
        /// </summary>
        /// <param name="files">The files you wish to scan. They are a tuple of file content and filename.</param>
        /// <returns>The scan results.</returns>
        public IEnumerable<ScanResult> ScanFiles(IEnumerable<Tuple<byte[], string>> files)
        {
            foreach (Tuple<byte[], string> fileInfo in files)
            {
                using (MemoryStream stream = new MemoryStream(fileInfo.Item1))
                    yield return ScanFile(stream, fileInfo.Item2);
            }
        }

        /// <summary>
        /// Scan multiple files.
        /// Note: It is highly encouraged to get the report of the files before scanning, in case it they already been scanned before.
        /// Note: Ýou are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
        /// </summary>
        /// <param name="streams">The streams you wish to scan. They are a tuple of stream and filename.</param>
        /// <returns>The scan results.</returns>
        public IEnumerable<ScanResult> ScanFiles(IEnumerable<Tuple<Stream, string>> streams)
        {
            foreach (Tuple<Stream, string> stream in streams)
            {
                yield return ScanFile(stream.Item1, stream.Item2);
            }
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
        /// <param name="resource">A hash of the file. It can be an MD5, SHA1 or SHA256</param>
        /// <returns>The scan results.</returns>
        public ScanResult RescanFile(string resource)
        {
            return RescanFiles(new[] { resource }).FirstOrDefault();
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file without sending the actual file to VirusTotal.
        /// Note: Before requesting a rescan you should retrieve the latest report on the file.
        /// </summary>
        /// <returns>The scan results.</returns>
        public ScanResult RescanFile(FileInfo file)
        {
            return RescanFiles(new[] { file }).FirstOrDefault();
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file without sending the actual file to VirusTotal.
        /// Note: Before requesting a rescan you should retrieve the latest report on the file.
        /// </summary>
        /// <returns>The scan results.</returns>
        public ScanResult RescanFile(byte[] file)
        {
            return RescanFiles(new[] { file }).FirstOrDefault();
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the files.
        /// </summary>
        /// <returns>The scan results.</returns>
        public List<ScanResult> RescanFiles(IEnumerable<byte[]> files)
        {
            return RescanFiles(GetResourcesFromFiles(files));
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the files.
        /// </summary>
        /// <returns>The scan results.</returns>
        public List<ScanResult> RescanFiles(IEnumerable<FileInfo> files)
        {
            return RescanFiles(GetResourcesFromFiles(files));
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the content of the streams to VirusTotal. It hashes the content and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the files.
        /// </summary>
        /// <returns>The scan results.</returns>
        public List<ScanResult> RescanFiles(IEnumerable<Stream> streams)
        {
            return RescanFiles(GetResourcesFromFiles(streams));
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the files.
        /// Note: You can use MD5, SHA1 or SHA256 and even mix them.
        /// Note: You can only request a maximum of 25 rescans.
        /// </summary>
        /// <param name="resourceList">a MD5, SHA1 or SHA256 of the files. You can also specify list made up of a combination of any of the three allowed hashes (up to 25 items), this allows you to perform a batch request with one single call.
        /// Note: that the files must already be present in the files store.
        /// </param>
        /// <returns>The scan results.</returns>
        public List<ScanResult> RescanFiles(IEnumerable<string> resourceList)
        {
            string[] hashes = resourceList as string[] ?? resourceList.ToArray();

            if (!hashes.Any())
                throw new ArgumentException("You have to supply a resource.", "resourceList");

            if (RestrictNumberOfResources && hashes.Length > 25)
                throw new ResourceLimitException("Too many hashes. There is a maximum of 25 hashes.");

            for (int i = 0; i < hashes.Length; i++)
            {
                ValidateResource(hashes[i]);
            }

            //https://www.virustotal.com/vtapi/v2/file/rescan
            RestRequest request = PrepareRequest("file/rescan");

            //Required
            request.AddParameter("resource", string.Join(",", hashes));

            //Output
            return GetResults<List<ScanResult>>(request);
        }

        /// <summary>
        /// Gets the report of the file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// </summary>
        /// <param name="file">The file you wish to get a report on.</param>
        public FileReport GetFileReport(byte[] file)
        {
            return GetFileReport(HashHelper.GetSHA256(file));
        }

        /// <summary>
        /// Gets the report of the file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// </summary>
        /// <param name="file">The file you wish to get a report on.</param>
        public FileReport GetFileReport(FileInfo file)
        {
            return GetFileReport(HashHelper.GetSHA256(file));
        }

        /// <summary>
        /// Gets the report of the file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// </summary>
        /// <param name="resource">The resource (MD5, SHA1 or SHA256) you wish to get a report on.</param>
        public FileReport GetFileReport(string resource)
        {
            return GetFileReports(new[] { resource }).First();
        }

        /// <summary>
        /// Gets a list of reports of the files.
        /// Note: This does not send the files to VirusTotal. It hashes the files and sends them instead.
        /// </summary>
        /// <param name="files">The files you wish to get reports on.</param>
        public List<FileReport> GetFileReports(IEnumerable<byte[]> files)
        {
            return GetFileReports(GetResourcesFromFiles(files));
        }

        /// <summary>
        /// Gets a list of reports of the files.
        /// Note: This does not send the files to VirusTotal. It hashes the files and sends them instead.
        /// </summary>
        /// <param name="files">The files you wish to get reports on.</param>
        public List<FileReport> GetFileReports(IEnumerable<FileInfo> files)
        {
            return GetFileReports(GetResourcesFromFiles(files));
        }

        /// <summary>
        /// Gets a list of reports of the files.
        /// Note: This does not send the content of the streams to VirusTotal. It hashes the content of the stream and sends that instead.
        /// </summary>
        /// <param name="streams">The streams you wish to get reports on.</param>
        public List<FileReport> GetFileReports(IEnumerable<Stream> streams)
        {
            return GetFileReports(GetResourcesFromFiles(streams));
        }

        /// <summary>
        /// Gets the report of the file represented by its hash or scan ID.
        /// Keep in mind that URLs sent using the API have the lowest scanning priority, depending on VirusTotal's load, it may take several hours before the file is scanned,
        /// so query the report at regular intervals until the result shows up and do not keep submitting the file over and over again.
        /// </summary>
        /// <param name="resourceList">SHA1, MD5 or SHA256 of the file. It can also be a scan ID of a previous scan.</param>
        /// <returns></returns>
        public List<FileReport> GetFileReports(IEnumerable<string> resourceList)
        {
            string[] hashes = resourceList as string[] ?? resourceList.ToArray();

            if (!hashes.Any())
                throw new ArgumentException("You have to supply a resource.", "resourceList");

            for (int i = 0; i < hashes.Length; i++)
            {
                ValidateResource(hashes[i]);
            }

            //https://www.virustotal.com/vtapi/v2/file/report
            RestRequest request = PrepareRequest("file/report");

            //Required
            request.AddParameter("resource", string.Join(",", hashes));

            //Output
            return GetResults<List<FileReport>>(request, true);
        }

        /// <summary>
        /// Scan the given URL. The URL will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest report on the URL.
        /// </summary>
        /// <param name="url">The url to process.</param>
        /// <returns>The scan results.</returns>
        public ScanResult ScanUrl(string url)
        {
            return ScanUrls(UrlToUri(new[] { url })).FirstOrDefault();
        }

        /// <summary>
        /// Scan the given URL. The URL will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest report on the URL.
        /// </summary>
        /// <param name="url">The url to process.</param>
        /// <returns>The scan results.</returns>
        public ScanResult ScanUrl(Uri url)
        {
            return ScanUrls(new[] { url }).FirstOrDefault();
        }

        /// <summary>
        /// Scan the given URLs. The URLs will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest reports on the URLs.
        /// </summary>
        /// <param name="urlList">The urls to process.</param>
        /// <returns>The scan results.</returns>
        public List<ScanResult> ScanUrls(IEnumerable<string> urlList)
        {
            return ScanUrls(UrlToUri(urlList));
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
                throw new ArgumentException("You have to supply an URL.", "urlList");

            //https://www.virustotal.com/vtapi/v2/url/scan
            RestRequest request = PrepareRequest("url/scan");

            //Required
            request.AddParameter("url", string.Join(Environment.NewLine, urls));

            //Output
            return GetResults<List<ScanResult>>(request);
        }

        /// <summary>
        /// Gets a scan report from an URL
        /// </summary>
        /// <param name="url">The URL you wish to get the report on.</param>
        /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URL if it is not present in the database.</param>
        /// <returns>A list of reports</returns>
        public UrlReport GetUrlReport(string url, bool scanIfNoReport = false)
        {
            return GetUrlReports(UrlToUri(new[] { url }), scanIfNoReport).FirstOrDefault();
        }

        /// <summary>
        /// Gets a scan report from an URL
        /// </summary>
        /// <param name="url">The URL you wish to get the report on.</param>
        /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URL if it is not present in the database.</param>
        /// <returns>A list of reports</returns>
        public UrlReport GetUrlReport(Uri url, bool scanIfNoReport = false)
        {
            return GetUrlReports(new[] { url }, scanIfNoReport).First();
        }

        /// <summary>
        /// Gets a scan report from a list of URLs
        /// </summary>
        /// <param name="urlList">The URLs you wish to get the reports on.</param>
        /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URLs if it is not present in the database.</param>
        /// <returns>A list of reports</returns>
        public List<UrlReport> GetUrlReports(IEnumerable<string> urlList, bool scanIfNoReport = false)
        {
            return GetUrlReports(UrlToUri(urlList), scanIfNoReport);
        }

        /// <summary>
        /// Gets a scan report from a list of URLs
        /// </summary>
        /// <param name="urlList">The URLs you wish to get the reports on.</param>
        /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URLs if it is not present in the database.</param>
        /// <returns>A list of reports</returns>
        public List<UrlReport> GetUrlReports(IEnumerable<Uri> urlList, bool scanIfNoReport = false)
        {
            IEnumerable<Uri> urls = urlList as Uri[] ?? urlList.ToArray();

            if (!urls.Any())
                throw new ArgumentException("You have to supply an URL.", "urlList");

            RestRequest request = PrepareRequest("url/report");

            //Required
            request.AddParameter("resource", string.Join(Environment.NewLine, urls));

            //Optional
            if (scanIfNoReport)
                request.AddParameter("scan", 1);

            //Output
            return GetResults<List<UrlReport>>(request, true);
        }

        /// <summary>
        /// Gets a scan report from an IP
        /// </summary>
        /// <param name="ip">The IP you wish to get the report on.</param>
        /// <returns>A report</returns>
        public IPReport GetIPReport(string ip)
        {
            return GetIPReport(IPAddress.Parse(ip));
        }

        /// <summary>
        /// Gets a scan report from an IP
        /// </summary>
        /// <param name="ip">The IP you wish to get the report on.</param>
        /// <returns>A report</returns>
        public IPReport GetIPReport(IPAddress ip)
        {
            if (ip == null)
                throw new ArgumentNullException("ip", "You have to supply an IP.");

            if (ip.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("Only IPv4 addresses are supported", "ip");

            RestRequest request = PrepareRequest("ip-address/report", Method.GET);

            //Required
            request.AddParameter("ip", ip.ToString());

            //Output
            return GetResults<IPReport>(request);
        }

        /// <summary>
        /// Gets a scan report from a domain
        /// </summary>
        /// <param name="domain">The domain you wish to get the report on.</param>
        /// <returns>A report</returns>
        public DomainReport GetDomainReport(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
                throw new ArgumentException("You have to supply a domain.", "domain");

            RestRequest request = PrepareRequest("domain/report", Method.GET);

            //Required
            request.AddParameter("domain", domain);

            //Output
            return GetResults<DomainReport>(request);
        }

        /// <summary>
        /// Creates a comment on a file denoted by its hash and/or scan ID.
        /// </summary>
        /// <param name="file">The file you wish to create a comment on</param>
        /// <param name="comment">The comment you wish to add.</param>
        /// <returns>A ScanResult object containing information about the resource.</returns>
        public ScanResult CreateComment(byte[] file, string comment)
        {
            return CreateComment(HashHelper.GetSHA256(file), comment);
        }

        /// <summary>
        /// Creates a comment on a file denoted by its hash and/or scan ID.
        /// </summary>
        /// <param name="file">The file you wish to create a comment on</param>
        /// <param name="comment">The comment you wish to add.</param>
        /// <returns>A ScanResult object containing information about the resource.</returns>
        public ScanResult CreateComment(FileInfo file, string comment)
        {
            return CreateComment(HashHelper.GetSHA256(file), comment);
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
            RestRequest request = PrepareRequest("comments/put");

            //Required
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

        private RestRequest PrepareRequest(string path, Method methodType = Method.POST)
        {
            RestRequest request = new RestRequest(path, methodType);

            //Required
            request.AddParameter("apikey", _apiKey);

            return request;
        }

        private T GetResults<T>(RestRequest request, bool applyHack = false)
        {
            RestResponse response = (RestResponse)_client.Execute(request);

            if (response.StatusCode == HttpStatusCode.NoContent)
                throw new RateLimitException("You have reached the 4 requests pr. min. limit of VirusTotal");

            if (response.StatusCode == HttpStatusCode.Forbidden)
                throw new AccessDeniedException("You don't have access to the service. Make sure your API key is working correctly.");

            if (response.ErrorException != null)
                throw response.ErrorException;

            if (response.StatusCode != HttpStatusCode.OK)
                throw new Exception("API gave error code " + response.StatusCode);

            if (string.IsNullOrWhiteSpace(response.Content))
                throw new Exception("There were no content in the response.");

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
            if (!url.ToLower().StartsWith("http://") && !url.ToLower().StartsWith("https://"))
                url = "http://" + url;

            return new Uri(url).ToString();
        }

        private IEnumerable<string> GetResourcesFromFiles(IEnumerable<FileInfo> files)
        {
            foreach (FileInfo fileInfo in files)
            {
                yield return HashHelper.GetSHA256(fileInfo);
            }
        }

        private IEnumerable<string> GetResourcesFromFiles(IEnumerable<byte[]> files)
        {
            foreach (byte[] fileBytes in files)
            {
                yield return HashHelper.GetSHA256(fileBytes);
            }
        }

        private IEnumerable<string> GetResourcesFromFiles(IEnumerable<Stream> streams)
        {
            foreach (Stream stream in streams)
            {
                yield return HashHelper.GetSHA256(stream);
            }
        }

        private IEnumerable<Uri> UrlToUri(IEnumerable<string> urls)
        {
            foreach (string url in urls)
            {
                Uri uri;
                try
                {
                    string tempUri = url.Trim();

                    if (!tempUri.StartsWith("http://") && !tempUri.StartsWith("https://"))
                        tempUri = "http://" + tempUri;

                    uri = new Uri(tempUri);
                }
                catch (Exception ex)
                {
                    throw new Exception("There was an error converting " + url + " to an uri. See InnerException for details.", ex);
                }

                yield return uri;
            }
        }

        private void ValidateResource(string resource)
        {
            if (string.IsNullOrWhiteSpace(resource))
                throw new ArgumentException("Resource must not be null or whitespace", "resource");

            if (resource.Length != 32 && resource.Length != 40 && resource.Length != 64 && resource.Length != 75)
                throw new InvalidResourceException("Resource " + resource + " has to be either a MD5, SHA1, SHA256 or scan id");
        }
    }
}