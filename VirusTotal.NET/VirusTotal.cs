using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using VirusTotalNET.Exceptions;
using VirusTotalNET.Results;

namespace VirusTotalNET
{
    public class VirusTotal
    {
        private readonly HttpClient _client;
        private bool _useTls;
        private readonly HttpClientHandler _httpClientHandler;
        private readonly Dictionary<string, string> _defaultValues;
        private readonly JsonSerializer _serializer;

        /// <summary>
        /// Public constructor for VirusTotal.
        /// </summary>
        /// <param name="apiKey">The API key you got from Virus Total</param>
        /// <exception cref="ArgumentException"></exception>
        public VirusTotal(string apiKey)
        {
            if (string.IsNullOrEmpty(apiKey) || apiKey.Length < 64)
                throw new ArgumentException("You have to set an API key.", nameof(apiKey));

            _defaultValues = new Dictionary<string, string>();
            _defaultValues.Add("apikey", apiKey);

            _httpClientHandler = new HttpClientHandler();
            _httpClientHandler.AllowAutoRedirect = false;

            _serializer = JsonSerializer.Create();
            _serializer.NullValueHandling = NullValueHandling.Ignore;

            _client = new HttpClient(_httpClientHandler);

            ApiUrl = "www.virustotal.com/vtapi/v2/";

            FileSizeLimit = 33553369; //32 MB - 1063 = 33553369 it is the effective limit by virus total
            RestrictSizeLimits = true;
            RestrictNumberOfResources = true;
            DumpRawJSON = false;
            DumpFolder = "%TEMP%";
        }

        internal VirusTotal(string apiKey, JsonSerializerSettings settings) : this(apiKey)
        {
            _serializer = JsonSerializer.Create(settings);
        }

        /// <summary>
        /// Dumps the raw JSON from VirusTotal into the folder specified in "DumpFolder". For debug purposes only.
        /// Defaults to false.
        /// </summary>
        public bool DumpRawJSON { get; set; }

        /// <summary>
        /// When DumpRawJSON is set to true, it dumps the raw JSON files to this folder. The files are named [DateTimeInUTC]-[RandomGUID].json
        /// Defaults to %TEMP%
        /// </summary>
        public string DumpFolder { get; set; }

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

                if (oldUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                    oldUrl = oldUrl.Substring(8);
                else if (oldUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                    oldUrl = oldUrl.Substring(7);

                _client.BaseAddress = _useTls ? new Uri("https://" + oldUrl) : new Uri("http://" + oldUrl);
            }
        }

        /// <summary>
        /// The user-agent to use when doing queries
        /// </summary>
        public string UserAgent { get { return _client.DefaultRequestHeaders.UserAgent.ToString(); } set { _client.DefaultRequestHeaders.Add("User-Agent", value); } }

        /// <summary>
        /// Get or set the proxy.
        /// </summary>
        public IWebProxy Proxy { get { return _httpClientHandler.Proxy; } set { _httpClientHandler.Proxy = value; } }

        /// <summary>
        /// Get or set the timeout.
        /// </summary>
        public TimeSpan Timeout { get { return _client.Timeout; } set { _client.Timeout = value; } }

        /// <summary>
        /// The URL which the Virus Total service listens on. IF you don't set the scheme to http:// or https:// it will default to https.
        /// </summary>
        public string ApiUrl
        {
            get { return _client.BaseAddress.ToString(); }
            set
            {
                string newUrl = value.Trim();

                if (string.IsNullOrWhiteSpace(newUrl))
                    return;

                if (newUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    _useTls = true;
                    newUrl = newUrl.Substring(8);
                }
                else if (newUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                {
                    _useTls = false;
                    newUrl = newUrl.Substring(7);
                }
                else
                    _useTls = true;

                _client.BaseAddress = _useTls ? new Uri("https://" + newUrl) : new Uri("http://" + newUrl);
            }
        }

        /// <summary>
        /// Scan a file.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// </summary>
        /// <param name="file">The file to scan</param>
        /// <returns>The scan results.</returns>
        public Task<ScanResult> ScanFile(FileInfo file)
        {
            if (!file.Exists)
                throw new FileNotFoundException("The file was not found.", file.Name);

            return ScanFile(file.OpenRead(), file.Name);
        }

        /// <summary>
        /// Scan a file.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// Note: You are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
        /// </summary>
        /// <param name="file">The file to scan</param>
        /// <param name="filename">The filename of the file</param>
        /// <returns>The scan results.</returns>
        public Task<ScanResult> ScanFile(byte[] file, string filename)
        {
            return ScanFile(new MemoryStream(file), filename);
        }

        /// <summary>
        /// Scan a file.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// Note: You are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
        /// </summary>
        /// <param name="fileStream">The file to scan</param>
        /// <param name="filename">The filename of the file</param>
        /// <returns>The scan results.</returns>
        public Task<ScanResult> ScanFile(Stream fileStream, string filename)
        {
            if (fileStream == null || fileStream.Length <= 0)
                throw new ArgumentException("You must provide a file", nameof(fileStream));

            if (RestrictSizeLimits && fileStream.Length > FileSizeLimit)
                throw new SizeLimitException(string.Format("The filesize limit on VirusTotal is {0} KB. Your file is {1} KB", FileSizeLimit / 1024, fileStream.Length / 1024));

            if (string.IsNullOrWhiteSpace(filename))
                throw new ArgumentException("You must provide a filename. Preferably the original filename.");

            MultipartFormDataContent multi = new MultipartFormDataContent();
            multi.Add(CreateApiPart());
            multi.Add(CreateFileContent(fileStream, filename, "application/octet-stream"));

            //https://www.virustotal.com/vtapi/v2/file/scan
            return GetResult<ScanResult>("file/scan", HttpMethod.Post, multi);
        }

        /// <summary>
        /// Scan multiple files.
        /// Note: It is highly encouraged to get the report of the files before scanning, in case it they already been scanned before.
        /// Note: You are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
        /// </summary>
        /// <param name="files">The files you wish to scan. They are a tuple of file content and filename.</param>
        /// <returns>The scan results.</returns>
        public IEnumerable<Task<ScanResult>> ScanFiles(IEnumerable<Tuple<byte[], string>> files)
        {
            foreach (Tuple<byte[], string> fileInfo in files)
            {
                yield return ScanFile(fileInfo.Item1, fileInfo.Item2);
            }
        }

        /// <summary>
        /// Scan multiple files.
        /// Note: It is highly encouraged to get the report of the files before scanning, in case it they already been scanned before.
        /// Note: You are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
        /// </summary>
        /// <param name="streams">The streams you wish to scan. They are a tuple of stream and filename.</param>
        /// <returns>The scan results.</returns>
        public IEnumerable<Task<ScanResult>> ScanFiles(IEnumerable<Tuple<Stream, string>> streams)
        {
            foreach (Tuple<Stream, string> stream in streams)
            {
                yield return ScanFile(stream.Item1, stream.Item2);
            }
        }

        /// <summary>
        /// Scan a file.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// </summary>
        /// <param name="bytes">Bytes that will be scaned</param>
        /// <param name="fileName">File name</param>
        /// <returns>The scan results.</returns>
        public ScanResult ScanFile(byte[] bytes, string fileName)
        {
            if (bytes == null || (bytes != null && !bytes.Any()))
                throw new FileNotFoundException("No bytes received.");

            //https://www.virustotal.com/vtapi/v2/file/scan
            RestRequest request = new RestRequest("file/scan", Method.POST);

            //Required
            request.AddParameter("apikey", _apiKey);

            if (bytes.Length <= FileSizeLimit)
                request.AddFile("file", bytes, fileName);
            else
                throw new SizeLimitException("The filesize limit on VirusTotal is 32 MB. Your file is " + bytes.Length / 1024 / 1024 + " MB");

            //Output
            return GetResults<ScanResult>(request);
        }

        /// <summary>
        /// Scan multiple files.
        /// Note: It is highly encouraged to get the report of the files before scanning, in case it they already been scanned before.
        /// </summary>
        /// <param name="files">The files you wish to scan.</param>
        /// <returns>The scan results.</returns>
        public IEnumerable<Task<ScanResult>> ScanFiles(IEnumerable<FileInfo> files)
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
        public Task<RescanResult> RescanFile(FileInfo file)
        {
            return RescanFile(GetResourcesFromFiles(file).First());
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file without sending the actual file to VirusTotal.
        /// Note: Before requesting a rescan you should retrieve the latest report on the file.
        /// </summary>
        /// <returns>The scan results.</returns>
        public Task<RescanResult> RescanFile(byte[] file)
        {
            return RescanFile(GetResourcesFromFiles(file).First());
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the files.
        /// </summary>
        /// <returns>The scan results.</returns>
        public Task<List<RescanResult>> RescanFiles(IEnumerable<byte[]> files)
        {
            return RescanFiles(GetResourcesFromFiles(files.ToArray()));
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the files.
        /// </summary>
        /// <returns>The scan results.</returns>
        public Task<List<RescanResult>> RescanFiles(IEnumerable<FileInfo> files)
        {
            return RescanFiles(GetResourcesFromFiles(files.ToArray()));
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the content of the streams to VirusTotal. It hashes the content and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the files.
        /// </summary>
        /// <returns>The scan results.</returns>
        public Task<List<RescanResult>> RescanFiles(IEnumerable<Stream> streams)
        {
            return RescanFiles(GetResourcesFromFiles(streams.ToArray()));
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
        public Task<List<RescanResult>> RescanFiles(IEnumerable<string> resourceList)
        {
            string[] hashes = resourceList as string[] ?? resourceList.ToArray();

            if (!hashes.Any())
                throw new ArgumentException("You have to supply a resource.", nameof(resourceList));

            if (RestrictNumberOfResources && hashes.Length > 25)
                throw new ResourceLimitException("Too many hashes. There is a maximum of 25 hashes.");

            for (int i = 0; i < hashes.Length; i++)
            {
                ValidateResource(hashes[i]);
            }

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("resource", string.Join(",", hashes));

            //https://www.virustotal.com/vtapi/v2/file/rescan
            return GetResults<RescanResult>("file/rescan", HttpMethod.Post, CreateContent(values));
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file without sending the actual file to VirusTotal.
        /// Note: Before requesting a rescan you should retrieve the latest report on the file.
        /// </summary>
        /// <param name="resource">A hash of the file. It can be an MD5, SHA1 or SHA256</param>
        /// <returns>The scan results.</returns>
        public Task<RescanResult> RescanFile(string resource)
        {
            if (string.IsNullOrWhiteSpace(resource))
                throw new ArgumentException("You have to supply a resource.", nameof(resource));

            ValidateResource(resource);

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("resource", resource);

            //https://www.virustotal.com/vtapi/v2/file/rescan
            return GetResult<RescanResult>("file/rescan", HttpMethod.Post, CreateContent(values));
        }

        /// <summary>
        /// Gets the report of the file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// </summary>
        /// <param name="file">The file you wish to get a report on.</param>
        public Task<FileReport> GetFileReport(byte[] file)
        {
            return GetFileReport(HashHelper.GetSHA256(file));
        }

        /// <summary>
        /// Gets the report of the file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// </summary>
        /// <param name="file">The file you wish to get a report on.</param>
        public Task<FileReport> GetFileReport(FileInfo file)
        {
            return GetFileReport(HashHelper.GetSHA256(file));
        }

        /// <summary>
        /// Gets a list of reports of the files.
        /// Note: This does not send the files to VirusTotal. It hashes the files and sends them instead.
        /// </summary>
        /// <param name="files">The files you wish to get reports on.</param>
        public Task<List<FileReport>> GetFileReports(IEnumerable<byte[]> files)
        {
            return GetFileReports(GetResourcesFromFiles(files.ToArray()));
        }

        /// <summary>
        /// Gets a list of reports of the files.
        /// Note: This does not send the files to VirusTotal. It hashes the files and sends them instead.
        /// </summary>
        /// <param name="files">The files you wish to get reports on.</param>
        public Task<List<FileReport>> GetFileReports(IEnumerable<FileInfo> files)
        {
            return GetFileReports(GetResourcesFromFiles(files.ToArray()));
        }

        /// <summary>
        /// Gets a list of reports of the files.
        /// Note: This does not send the content of the streams to VirusTotal. It hashes the content of the stream and sends that instead.
        /// </summary>
        /// <param name="streams">The streams you wish to get reports on.</param>
        public Task<List<FileReport>> GetFileReports(IEnumerable<Stream> streams)
        {
            return GetFileReports(GetResourcesFromFiles(streams.ToArray()));
        }

        /// <summary>
        /// Gets the report of the file represented by its hash or scan ID.
        /// Keep in mind that URLs sent using the API have the lowest scanning priority, depending on VirusTotal's load, it may take several hours before the file is scanned,
        /// so query the report at regular intervals until the result shows up and do not keep submitting the file over and over again.
        /// </summary>
        /// <param name="resourceList">SHA1, MD5 or SHA256 of the file. It can also be a scan ID of a previous scan.</param>
        /// <returns></returns>
        public Task<List<FileReport>> GetFileReports(IEnumerable<string> resourceList)
        {
            string[] hashes = resourceList as string[] ?? resourceList.ToArray();

            if (!hashes.Any())
                throw new ArgumentException("You have to supply a resource.", nameof(resourceList));

            if (RestrictNumberOfResources && hashes.Length > 4)
                throw new ResourceLimitException("Too many hashes. There is a maximum of 4 hashes at the same time.");

            for (int i = 0; i < hashes.Length; i++)
            {
                ValidateResource(hashes[i]);
            }

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("resource", string.Join(",", hashes));

            //https://www.virustotal.com/vtapi/v2/file/report
            return GetResults<FileReport>("file/report", HttpMethod.Post, CreateContent(values));
        }

        /// <summary>
        /// Gets the report of the file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// </summary>
        /// <param name="resource">The resource (MD5, SHA1 or SHA256) you wish to get a report on.</param>
        public Task<FileReport> GetFileReport(string resource)
        {
            if (string.IsNullOrWhiteSpace(resource))
                throw new ArgumentException("You have to supply a resource.", nameof(resource));

            ValidateResource(resource);

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("resource", resource);

            //https://www.virustotal.com/vtapi/v2/file/report
            return GetResult<FileReport>("file/report", HttpMethod.Post, CreateContent(values));
        }

        /// <summary>
        /// Scan the given URL. The URL will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest report on the URL.
        /// </summary>
        /// <param name="url">The url to process.</param>
        /// <returns>The scan results.</returns>
        public Task<UrlScanResult> ScanUrl(string url)
        {
            return ScanUrl(UrlToUri(new[] { url }).First());
        }

        /// <summary>
        /// Scan the given URLs. The URLs will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest reports on the URLs.
        /// </summary>
        /// <param name="urlList">The urls to process.</param>
        /// <returns>The scan results.</returns>
        public Task<List<UrlScanResult>> ScanUrls(IEnumerable<string> urlList)
        {
            return ScanUrls(UrlToUri(urlList));
        }

        /// <summary>
        /// Scan the given URLs. The URLs will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest reports on the URLs.
        /// </summary>
        /// <param name="urlList">The urls to process.</param>
        /// <returns>The scan results.</returns>
        public Task<List<UrlScanResult>> ScanUrls(IEnumerable<Uri> urlList)
        {
            IEnumerable<Uri> urls = urlList as Uri[] ?? urlList.ToArray();

            if (!urls.Any())
                throw new ArgumentException("You have to supply an URL.", nameof(urlList));

            if (RestrictNumberOfResources && urls.Count() > 25)
                throw new ResourceLimitException("Too many URLs. There is a maximum of 25 URLs at the same time.");

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("url", string.Join(Environment.NewLine, urls));

            //https://www.virustotal.com/vtapi/v2/url/scan
            return GetResults<UrlScanResult>("url/scan", HttpMethod.Post, CreateContent(values));
        }

        /// <summary>
        /// Scan the given URL. The URL will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest report on the URL.
        /// </summary>
        /// <param name="url">The url to process.</param>
        /// <returns>The scan results.</returns>
        public Task<UrlScanResult> ScanUrl(Uri url)
        {
            if (url == null)
                throw new ArgumentNullException(nameof(url), "You have to supply an URL.");

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("url", url.ToString());

            //https://www.virustotal.com/vtapi/v2/url/scan
            return GetResult<UrlScanResult>("url/scan", HttpMethod.Post, CreateContent(values));
        }

        /// <summary>
        /// Gets a scan report from an URL
        /// </summary>
        /// <param name="url">The URL you wish to get the report on.</param>
        /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URL if it is not present in the database.</param>
        /// <returns>A list of reports</returns>
        public Task<UrlReport> GetUrlReport(string url, bool scanIfNoReport = false)
        {
            return GetUrlReport(UrlToUri(new[] { url }).First(), scanIfNoReport);
        }

        /// <summary>
        /// Gets a scan report from a list of URLs
        /// </summary>
        /// <param name="urlList">The URLs you wish to get the reports on.</param>
        /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URLs if it is not present in the database.</param>
        /// <returns>A list of reports</returns>
        public Task<List<UrlReport>> GetUrlReports(IEnumerable<string> urlList, bool scanIfNoReport = false)
        {
            return GetUrlReports(UrlToUri(urlList), scanIfNoReport);
        }

        /// <summary>
        /// Gets a scan report from a list of URLs
        /// </summary>
        /// <param name="urlList">The URLs you wish to get the reports on.</param>
        /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URLs if it is not present in the database.</param>
        /// <returns>A list of reports</returns>
        public Task<List<UrlReport>> GetUrlReports(IEnumerable<Uri> urlList, bool scanIfNoReport = false)
        {
            IEnumerable<Uri> urls = urlList as Uri[] ?? urlList.ToArray();

            if (!urls.Any())
                throw new ArgumentException("You have to supply an URL.", nameof(urlList));

            if (RestrictNumberOfResources && urls.Count() > 4)
                throw new ResourceLimitException("Too many URLs. There is a maximum of 4 urls at the time.");

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("resource", string.Join(Environment.NewLine, urls));

            //Optional
            if (scanIfNoReport)
                values.Add("scan", "1");

            //Output
            return GetResults<UrlReport>("url/report", HttpMethod.Post, CreateContent(values));
        }

        /// <summary>
        /// Gets a scan report from an URL
        /// </summary>
        /// <param name="url">The URL you wish to get the report on.</param>
        /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URL if it is not present in the database.</param>
        /// <returns>A list of reports</returns>
        public Task<UrlReport> GetUrlReport(Uri url, bool scanIfNoReport = false)
        {
            if (url == null)
                throw new ArgumentNullException(nameof(url), "You have to supply an URL.");

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("resource", url.ToString());

            //Optional
            if (scanIfNoReport)
                values.Add("scan", "1");

            //Output
            return GetResult<UrlReport>("url/report", HttpMethod.Post, CreateContent(values));
        }

        /// <summary>
        /// Gets a scan report from an list of IP addreses
        /// IMPORTANT: This method actually does a query pr. item, which can quickly result in you getting over your request limit.
        /// </summary>
        /// <param name="ips">The IPs you wish to get a report for.</param>
        /// <returns>A list of reports</returns>
        public IEnumerable<Task<IPReport>> GetIPReports(IEnumerable<IPAddress> ips)
        {
            foreach (IPAddress ip in ips)
            {
                yield return GetIPReport(ip);
            }
        }

        /// <summary>
        /// Gets a scan report from an list of IP addreses
        /// IMPORTANT: This method actually does a query pr. item, which can quickly result in you getting over your request limit.
        /// </summary>
        /// <param name="ips">The IPs you wish to get a report for.</param>
        /// <returns>A list of reports</returns>
        public IEnumerable<Task<IPReport>> GetIPReports(IEnumerable<string> ips)
        {
            foreach (string ip in ips)
            {
                yield return GetIPReport(ip);
            }
        }

        /// <summary>
        /// Gets a scan report from an IP
        /// </summary>
        /// <param name="ip">The IP you wish to get the report on.</param>
        /// <returns>A report</returns>
        public Task<IPReport> GetIPReport(string ip)
        {
            return GetIPReport(IPAddress.Parse(ip));
        }

        /// <summary>
        /// Gets a scan report from an IP
        /// </summary>
        /// <param name="ip">The IP you wish to get the report on.</param>
        /// <returns>A report</returns>
        public Task<IPReport> GetIPReport(IPAddress ip)
        {
            if (ip == null)
                throw new ArgumentNullException(nameof(ip), "You have to supply an IP.");

            if (ip.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("Only IPv4 addresses are supported", nameof(ip));

            //Hack because VT thought it was a good idea to have this API call as GET
            return GetResult<IPReport>("ip-address/report?apikey=" + _defaultValues["apikey"] + "&ip=" + ip, HttpMethod.Get, null);
        }

        /// <summary>
        /// Gets a scan report from a list of domains
        /// IMPORTANT: This method actually does a query pr. item, which can quickly result in you getting over your request limit.
        /// </summary>
        /// <param name="domains">The list of domains you wish to get reports for.</param>
        /// <returns>A list of reports</returns>
        public IEnumerable<Task<DomainReport>> GetDomainReports(IEnumerable<string> domains)
        {
            foreach (string domain in domains)
            {
                yield return GetDomainReport(domain);
            }
        }

        /// <summary>
        /// Gets a scan report from a domain
        /// </summary>
        /// <param name="domain">The domain you wish to get the report on.</param>
        /// <returns>A report</returns>
        public Task<DomainReport> GetDomainReport(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
                throw new ArgumentException("You have to supply a domain.", nameof(domain));

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("domain", domain);

            //Hack because VT thought it was a good idea to have this API call as GET
            return GetResult<DomainReport>("domain/report?apikey=" + _defaultValues["apikey"] + "&domain=" + domain, HttpMethod.Get, null);
        }

        /// <summary>
        /// Creates a comment on a file denoted by its hash and/or scan ID.
        /// </summary>
        /// <param name="file">The file you wish to create a comment on</param>
        /// <param name="comment">The comment you wish to add.</param>
        /// <returns>A ScanResult object containing information about the resource.</returns>
        public Task<ScanResult> CreateComment(byte[] file, string comment)
        {
            return CreateComment(HashHelper.GetSHA256(file), comment);
        }

        /// <summary>
        /// Creates a comment on a file denoted by its hash and/or scan ID.
        /// </summary>
        /// <param name="file">The file you wish to create a comment on</param>
        /// <param name="comment">The comment you wish to add.</param>
        /// <returns>A ScanResult object containing information about the resource.</returns>
        public Task<ScanResult> CreateComment(FileInfo file, string comment)
        {
            return CreateComment(HashHelper.GetSHA256(file), comment);
        }

        /// <summary>
        /// Creates a comment on a file denoted by its hash and/or scan ID.
        /// </summary>
        /// <param name="resource">The SHA256 hash or scan ID of the resource.</param>
        /// <param name="comment">The comment you wish to add.</param>
        /// <returns>A ScanResult object containing information about the resource.</returns>
        public Task<ScanResult> CreateComment(string resource, string comment)
        {
            ValidateResource(resource);

            if (string.IsNullOrWhiteSpace(comment))
                throw new ArgumentException("Comment must not be null or whitespace", nameof(comment));

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("resource", resource);
            values.Add("comment", comment);

            //https://www.virustotal.com/vtapi/v2/comments/put
            return GetResult<ScanResult>("comments/put", HttpMethod.Post, CreateContent(values));
        }

        private FormUrlEncodedContent CreateContent(IDictionary<string, string> values)
        {
            return new FormUrlEncodedContent(_defaultValues.Concat(values));
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

        private async Task<List<T>> GetResults<T>(string url, HttpMethod method, HttpContent content)
        {
            HttpResponseMessage response = await SendRequest<T>(url, method, content);

            using (Stream responseStream = await response.Content.ReadAsStreamAsync())
            using (StreamReader sr = new StreamReader(responseStream, Encoding.UTF8))
            using (JsonTextReader jsonTextReader = new JsonTextReader(sr))
            {
                jsonTextReader.CloseInput = false;

                DumpJSONIfDebug(responseStream);

                JToken token = JToken.Load(jsonTextReader);

                if (token.Type == JTokenType.Array)
                    return token.ToObject<List<T>>(_serializer);

                return new List<T> { token.ToObject<T>(_serializer) };
            }
        }

        private async Task<T> GetResult<T>(string url, HttpMethod method, HttpContent content)
        {
            HttpResponseMessage response = await SendRequest<T>(url, method, content);

            using (Stream responseStream = await response.Content.ReadAsStreamAsync())
            using (StreamReader sr = new StreamReader(responseStream, Encoding.UTF8))
            using (JsonTextReader jsonTextReader = new JsonTextReader(sr))
            {
                jsonTextReader.CloseInput = false;

                DumpJSONIfDebug(responseStream);

                return _serializer.Deserialize<T>(jsonTextReader);
            }
        }

        private void DumpJSONIfDebug(Stream stream)
        {
            if (!DumpRawJSON)
                return;

            string path = Environment.ExpandEnvironmentVariables(DumpFolder);

            if (!Directory.Exists(path))
                Directory.CreateDirectory(path);

            string filename = DateTime.UtcNow.ToString("yyyy-MM-dd_HH-mm-ss") + "-" + Guid.NewGuid() + ".json";
            string filePath = Path.Combine(path, filename);

            using (FileStream fs = File.OpenWrite(filePath))
                stream.CopyTo(fs);

            stream.Position = 0;
        }

        private async Task<HttpResponseMessage> SendRequest<T>(string url, HttpMethod method, HttpContent content)
        {
            HttpRequestMessage request = new HttpRequestMessage(method, url);
            request.Content = content;

            HttpResponseMessage response = await _client.SendAsync(request);

            if (response.StatusCode == HttpStatusCode.NoContent)
                throw new RateLimitException("You have reached the 4 requests pr. min. limit of VirusTotal");

            if (response.StatusCode == HttpStatusCode.Forbidden)
                throw new AccessDeniedException("You don't have access to the service. Make sure your API key is working correctly.");

            if (response.StatusCode != HttpStatusCode.OK)
                throw new Exception("API gave error code " + response.StatusCode);

            if (string.IsNullOrWhiteSpace(response.Content.ToString()))
                throw new Exception("There were no content in the response.");

            return response;
        }

        private string NormalizeUrl(string url)
        {
            Uri uri = CreateUri(url);
            return uri.ToString();
        }

        private IEnumerable<string> GetResourcesFromFiles(params FileInfo[] files)
        {
            foreach (FileInfo fileInfo in files)
            {
                yield return HashHelper.GetSHA256(fileInfo);
            }
        }

        private IEnumerable<string> GetResourcesFromFiles(params byte[][] files)
        {
            foreach (byte[] fileBytes in files)
            {
                yield return HashHelper.GetSHA256(fileBytes);
            }
        }

        private IEnumerable<string> GetResourcesFromFiles(params Stream[] streams)
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
                    uri = CreateUri(url);
                }
                catch (Exception ex)
                {
                    throw new Exception("There was an error converting " + url + " to an uri. See InnerException for details.", ex);
                }

                yield return uri;
            }
        }

        private Uri CreateUri(string url)
        {
            string tempUri = url.Trim();
            string lowered = tempUri.ToLower();

            if (!lowered.StartsWith("http://") && !lowered.StartsWith("https://"))
                tempUri = "http://" + tempUri;

            return new Uri(tempUri);
        }

        private void ValidateResource(string resource)
        {
            if (string.IsNullOrWhiteSpace(resource))
                throw new ArgumentException("Resource must not be null or whitespace", nameof(resource));

            if (resource.Length != 32 && resource.Length != 40 && resource.Length != 64 && resource.Length != 75)
                throw new InvalidResourceException("Resource " + resource + " has to be either a MD5, SHA1, SHA256 or scan id");
        }

        private HttpContent CreateApiPart()
        {
            HttpContent content = new StringContent(_defaultValues["apikey"]);
            content.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data")
            {
                Name = "\"apikey\""
            };

            return content;
        }

        private StreamContent CreateFileContent(Stream stream, string fileName, string contentType)
        {
            var fileContent = new StreamContent(stream);
            fileContent.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data")
            {
                Name = "\"file\"",
                FileName = "\"" + fileName + "\""
            };
            fileContent.Headers.ContentType = new MediaTypeHeaderValue(contentType);
            return fileContent;
        }
    }
}