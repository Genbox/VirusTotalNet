using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using VirusTotalNET.Exceptions;
using VirusTotalNET.Helpers;
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

        /// <param name="apiKey">The API key you got from Virus Total</param>
        public VirusTotal(string apiKey)
        {
            if (string.IsNullOrWhiteSpace(apiKey) || apiKey.Length < 64)
                throw new ArgumentException("You have to set an API key.", nameof(apiKey));

            _defaultValues = new Dictionary<string, string>(1);
            _defaultValues.Add("apikey", apiKey);

            _httpClientHandler = new HttpClientHandler();
            _httpClientHandler.AllowAutoRedirect = false;

            _serializer = JsonSerializer.Create();
            _serializer.NullValueHandling = NullValueHandling.Ignore;

            _client = new HttpClient(_httpClientHandler);

            ApiUrl = "www.virustotal.com/vtapi/v2/";

            RestrictSizeLimits = true;
            RestrictNumberOfResources = true;
        }

        internal VirusTotal(string apiKey, JsonSerializerSettings settings) : this(apiKey)
        {
            _serializer = JsonSerializer.Create(settings);
        }

        /// <summary>
        /// Occurs when the raw JSON response is received from VirusTotal.
        /// </summary>
        public event Action<byte[]> OnRawResponseReceived;

        /// <summary>
        /// Occurs just before we send a request to VirusTotal.
        /// </summary>
        public event Action<HttpRequestMessage> OnHTTPRequestSending;

        /// <summary>
        /// Occurs right after a response has been received from VirusTotal.
        /// </summary>
        public event Action<HttpResponseMessage> OnHTTPResponseReceived;

        /// <summary>
        /// When true, we check the file size before uploading it to Virus Total. The file size restrictions are based on the Virus Total public API 2.0 documentation.
        /// </summary>
        public bool RestrictSizeLimits { get; set; }

        /// <summary>
        /// When true, we check the number of resources that are submitted to Virus Total. The limits are according to Virus Total public API 2.0 documentation.
        /// </summary>
        public bool RestrictNumberOfResources { get; set; }

        /// <summary>
        /// The maximum size (in bytes) that the Virus Total public API 2.0 supports for file uploads.
        /// </summary>
        public long FileSizeLimit { get; set; } = 33553369; //32 MB - 1063 = 33553369 it is the effective limit by virus total as it measures file size limit on the TOTAL request size, and not just the file content.

        /// <summary>
        /// The maximum size (in bytes) of comments.
        /// </summary>
        public int CommentSizeRestriction { get; set; } = 4096;

        /// <summary>
        /// The maximum number of resources you can rescan in one request.
        /// </summary>
        public int RescanBatchSizeLimit { get; set; } = 25;

        /// <summary>
        /// The maximum number of resources you can get file reports for in one request.
        /// </summary>
        public int FileReportBatchSizeLimit { get; set; } = 4;

        /// <summary>
        /// The maximum number of URLs you can get reports for in one request.
        /// </summary>
        public int UrlReportBatchSizeLimit { get; set; } = 4;

        /// <summary>
        /// The maximum number of URLs you can scan in one request.
        /// </summary>
        public int UrlScanBatchSizeLimit { get; set; } = 25;

        /// <summary>
        /// Set to false to use HTTP instead of HTTPS. HTTPS is used by default.
        /// </summary>
        public bool UseTLS
        {
            get => _useTls;
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
        public string UserAgent
        {
            get => _client.DefaultRequestHeaders.UserAgent.ToString();
            set => _client.DefaultRequestHeaders.Add("User-Agent", value);
        }

        /// <summary>
        /// Get or set the proxy.
        /// </summary>
        public IWebProxy Proxy
        {
            get => _httpClientHandler.Proxy;
            set => _httpClientHandler.Proxy = value;
        }

        /// <summary>
        /// Get or set the timeout.
        /// </summary>
        public TimeSpan Timeout
        {
            get => _client.Timeout;
            set => _client.Timeout = value;
        }

        /// <summary>
        /// The URL which the Virus Total service listens on. If you don't set the scheme to http:// or https:// it will default to https://
        /// </summary>
        public string ApiUrl
        {
            get => _client.BaseAddress.ToString();
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
        public Task<ScanResult> ScanFileAsync(FileInfo file)
        {
            if (!file.Exists)
                throw new FileNotFoundException("The file was not found.", file.Name);

            return ScanFileAsync(file.OpenRead(), file.Name);
        }

        /// <summary>
        /// Scan a file.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// Note: You are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
        /// </summary>
        /// <param name="file">The file to scan</param>
        /// <param name="filename">The filename of the file</param>
        public Task<ScanResult> ScanFileAsync(byte[] file, string filename)
        {
            return ScanFileAsync(new MemoryStream(file), filename);
        }

        /// <summary>
        /// Scan a file.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// Note: You are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
        /// </summary>
        /// <param name="stream">The file to scan</param>
        /// <param name="filename">The filename of the file</param>
        public Task<ScanResult> ScanFileAsync(Stream stream, string filename)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream), "You must provide a stream that is not null");

            if (stream.Length <= 0)
                throw new ArgumentException("You must provide a stream with content", nameof(stream));

            if (RestrictSizeLimits && stream.Length > FileSizeLimit)
                throw new SizeLimitException(FileSizeLimit, stream.Length);

            if (string.IsNullOrWhiteSpace(filename))
                throw new ArgumentException("You must provide a filename. Preferably the original filename.");

            MultipartFormDataContent multi = new MultipartFormDataContent();
            multi.Add(CreateApiPart());
            multi.Add(CreateFileContent(stream, filename));

            //https://www.virustotal.com/vtapi/v2/file/scan
            return GetResult<ScanResult>("file/scan", HttpMethod.Post, multi);
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the file.
        /// </summary>
        public Task<RescanResult> RescanFileAsync(FileInfo file)
        {
            return RescanFileAsync(ResourcesHelper.GetResourceIdentifier(file));
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the file.
        /// </summary>
        public Task<RescanResult> RescanFileAsync(byte[] file)
        {
            return RescanFileAsync(ResourcesHelper.GetResourceIdentifier(file));
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the file.
        /// </summary>
        public Task<RescanResult> RescanFileAsync(Stream stream)
        {
            return RescanFileAsync(ResourcesHelper.GetResourceIdentifier(stream));
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file without sending the actual file to VirusTotal.
        /// Note: Before requesting a rescan you should retrieve the latest report on the file.
        /// </summary>
        /// <param name="resource">A hash of the file. It can be an MD5, SHA1 or SHA256</param>
        public Task<RescanResult> RescanFileAsync(string resource)
        {
            resource = ResourcesHelper.ValidateResourcea(resource, ResourceType.AnyHash);

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("resource", resource);

            //https://www.virustotal.com/vtapi/v2/file/rescan
            return GetResult<RescanResult>("file/rescan", HttpMethod.Post, CreateURLEncodedContent(values));
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the files.
        /// </summary>
        public Task<IEnumerable<RescanResult>> RescanFilesAsync(IEnumerable<FileInfo> files)
        {
            return RescanFilesAsync(ResourcesHelper.GetResourceIdentifier(files));
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the files.
        /// </summary>
        public Task<IEnumerable<RescanResult>> RescanFilesAsync(IEnumerable<byte[]> files)
        {
            return RescanFilesAsync(ResourcesHelper.GetResourceIdentifier(files));
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the content of the streams to VirusTotal. It hashes the content and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the files.
        /// </summary>
        public Task<IEnumerable<RescanResult>> RescanFilesAsync(IEnumerable<Stream> streams)
        {
            return RescanFilesAsync(ResourcesHelper.GetResourceIdentifier(streams));
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the files.
        /// Note: You can use MD5, SHA1 or SHA256 and even mix them.
        /// Note: You can only request a maximum of 25 rescans at the time.
        /// </summary>
        /// <param name="resourceList">a MD5, SHA1 or SHA256 of the files. You can also specify list made up of a combination of any of the three allowed hashes (up to 25 items), this allows you to perform a batch request with one single call.</param>
        public Task<IEnumerable<RescanResult>> RescanFilesAsync(IEnumerable<string> resourceList)
        {
            resourceList = ResourcesHelper.ValidateResourcea(resourceList, ResourceType.AnyHash);

            string[] resources = resourceList as string[] ?? resourceList.ToArray();

            if (RestrictNumberOfResources && resources.Length > RescanBatchSizeLimit)
                throw new ResourceLimitException($"Too many resources. There is a maximum of {RescanBatchSizeLimit} resources at the time.");

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("resource", string.Join(",", resources));

            //https://www.virustotal.com/vtapi/v2/file/rescan
            return GetResults<RescanResult>("file/rescan", HttpMethod.Post, CreateURLEncodedContent(values));
        }

        /// <summary>
        /// Gets the report of the file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// </summary>
        /// <param name="file">The file you want to get a report on.</param>
        public Task<FileReport> GetFileReportAsync(byte[] file)
        {
            return GetFileReportAsync(ResourcesHelper.GetResourceIdentifier(file));
        }

        /// <summary>
        /// Gets the report of the file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// </summary>
        /// <param name="file">The file you want to get a report on.</param>
        public Task<FileReport> GetFileReportAsync(FileInfo file)
        {
            return GetFileReportAsync(ResourcesHelper.GetResourceIdentifier(file));
        }

        /// <summary>
        /// Gets the report of the file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// </summary>
        /// <param name="stream">The stream you want to get a report on.</param>
        public Task<FileReport> GetFileReportAsync(Stream stream)
        {
            return GetFileReportAsync(ResourcesHelper.GetResourceIdentifier(stream));
        }

        /// <summary>
        /// Gets the report of the file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// </summary>
        /// <param name="resource">The resource (MD5, SHA1 or SHA256) you wish to get a report on.</param>
        public Task<FileReport> GetFileReportAsync(string resource)
        {
            resource = ResourcesHelper.ValidateResourcea(resource, ResourceType.AnyHash | ResourceType.ScanId);

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("resource", resource);

            //https://www.virustotal.com/vtapi/v2/file/report
            return GetResult<FileReport>("file/report", HttpMethod.Post, CreateURLEncodedContent(values));
        }

        /// <summary>
        /// Gets a list of reports of the files.
        /// Note: This does not send the files to VirusTotal. It hashes the files and sends them instead.
        /// </summary>
        /// <param name="files">The files you want to get reports on.</param>
        public Task<IEnumerable<FileReport>> GetFileReportsAsync(IEnumerable<byte[]> files)
        {
            return GetFileReportsAsync(ResourcesHelper.GetResourceIdentifier(files));
        }

        /// <summary>
        /// Gets a list of reports of the files.
        /// Note: This does not send the files to VirusTotal. It hashes the files and sends them instead.
        /// </summary>
        /// <param name="files">The files you want to get reports on.</param>
        public Task<IEnumerable<FileReport>> GetFileReportsAsync(IEnumerable<FileInfo> files)
        {
            return GetFileReportsAsync(ResourcesHelper.GetResourceIdentifier(files));
        }

        /// <summary>
        /// Gets a list of reports of the files.
        /// Note: This does not send the content of the streams to VirusTotal. It hashes the content of the stream and sends that instead.
        /// </summary>
        /// <param name="streams">The streams you want to get reports on.</param>
        public Task<IEnumerable<FileReport>> GetFileReportsAsync(IEnumerable<Stream> streams)
        {
            return GetFileReportsAsync(ResourcesHelper.GetResourceIdentifier(streams));
        }

        /// <summary>
        /// Gets the report of the file represented by its hash or scan ID.
        /// Keep in mind that URLs sent using the API have the lowest scanning priority, depending on VirusTotal's load, it may take several hours before the file is scanned,
        /// so query the report at regular intervals until the result shows up and do not keep submitting the file over and over again.
        /// </summary>
        /// <param name="resourceList">SHA1, MD5 or SHA256 of the file. It can also be a scan ID of a previous scan.</param>
        public Task<IEnumerable<FileReport>> GetFileReportsAsync(IEnumerable<string> resourceList)
        {
            resourceList = ResourcesHelper.ValidateResourcea(resourceList, ResourceType.AnyHash | ResourceType.ScanId);

            string[] resources = resourceList as string[] ?? resourceList.ToArray();

            if (RestrictNumberOfResources && resources.Length > FileReportBatchSizeLimit)
                throw new ResourceLimitException($"Too many hashes. There is a maximum of {FileReportBatchSizeLimit} resources at the same time.");

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("resource", string.Join(",", resources));

            //https://www.virustotal.com/vtapi/v2/file/report
            return GetResults<FileReport>("file/report", HttpMethod.Post, CreateURLEncodedContent(values));
        }

        /// <summary>
        /// Scan the given URL. The URL will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest report on the URL.
        /// </summary>
        /// <param name="url">The URL to process.</param>
        public Task<UrlScanResult> ScanUrlAsync(string url)
        {
            url = ResourcesHelper.ValidateResourcea(url, ResourceType.URL);

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("url", url);

            //https://www.virustotal.com/vtapi/v2/url/scan
            return GetResult<UrlScanResult>("url/scan", HttpMethod.Post, CreateURLEncodedContent(values));
        }

        /// <summary>
        /// Scan the given URL. The URL will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest report on the URL.
        /// </summary>
        /// <param name="url">The URL to process.</param>
        public Task<UrlScanResult> ScanUrlAsync(Uri url)
        {
            return ScanUrlAsync(url.ToString());
        }

        /// <summary>
        /// Scan the given URLs. The URLs will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest reports on the URLs.
        /// </summary>
        /// <param name="urls">The URLs to process.</param>
        public Task<IEnumerable<UrlScanResult>> ScanUrlsAsync(IEnumerable<string> urls)
        {
            urls = ResourcesHelper.ValidateResourcea(urls, ResourceType.URL);

            string[] urlCast = urls as string[] ?? urls.ToArray();

            if (RestrictNumberOfResources && urlCast.Length > UrlScanBatchSizeLimit)
                throw new ResourceLimitException($"Too many URLs. There is a maximum of {UrlScanBatchSizeLimit} URLs at the same time.");

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("url", string.Join(Environment.NewLine, urlCast));

            //https://www.virustotal.com/vtapi/v2/url/scan
            return GetResults<UrlScanResult>("url/scan", HttpMethod.Post, CreateURLEncodedContent(values));
        }

        /// <summary>
        /// Scan the given URLs. The URLs will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest reports on the URLs.
        /// </summary>
        /// <param name="urlList">The URLs to process.</param>
        public Task<IEnumerable<UrlScanResult>> ScanUrlsAsync(IEnumerable<Uri> urlList)
        {
            return ScanUrlsAsync(urlList.Select(x => x.ToString()));
        }

        /// <summary>
        /// Gets a scan report from an URL
        /// </summary>
        /// <param name="url">The URL you wish to get the report on.</param>
        /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URL if it is not present in the database.</param>
        public Task<UrlReport> GetUrlReportAsync(string url, bool scanIfNoReport = false)
        {
            url = ResourcesHelper.ValidateResourcea(url, ResourceType.URL | ResourceType.ScanId);

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("resource", url);

            //Optional
            if (scanIfNoReport)
                values.Add("scan", "1");

            //Output
            return GetResult<UrlReport>("url/report", HttpMethod.Post, CreateURLEncodedContent(values));
        }

        /// <summary>
        /// Gets a scan report from an URL
        /// </summary>
        /// <param name="url">The URL you wish to get the report on.</param>
        /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URL if it is not present in the database.</param>
        public Task<UrlReport> GetUrlReportAsync(Uri url, bool scanIfNoReport = false)
        {
            return GetUrlReportAsync(url.ToString(), scanIfNoReport);
        }

        /// <summary>
        /// Gets a scan report from a list of URLs
        /// </summary>
        /// <param name="urls">The URLs you wish to get the reports on.</param>
        /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URLs if it is not present in the database.</param>
        public Task<IEnumerable<UrlReport>> GetUrlReportsAsync(IEnumerable<string> urls, bool scanIfNoReport = false)
        {
            urls = ResourcesHelper.ValidateResourcea(urls, ResourceType.URL);

            string[] urlCast = urls as string[] ?? urls.ToArray();

            if (RestrictNumberOfResources && urlCast.Length > UrlReportBatchSizeLimit)
                throw new ResourceLimitException($"Too many URLs. There is a maximum of {UrlReportBatchSizeLimit} urls at the time.");

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("resource", string.Join(Environment.NewLine, urlCast));

            //Optional
            if (scanIfNoReport)
                values.Add("scan", "1");

            //Output
            return GetResults<UrlReport>("url/report", HttpMethod.Post, CreateURLEncodedContent(values));
        }

        /// <summary>
        /// Gets a scan report from a list of URLs
        /// </summary>
        /// <param name="urlList">The URLs you wish to get the reports on.</param>
        /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URLs if it is not present in the database.</param>
        public Task<IEnumerable<UrlReport>> GetUrlReportsAsync(IEnumerable<Uri> urlList, bool scanIfNoReport = false)
        {
            return GetUrlReportsAsync(urlList.Select(x => x.ToString()), scanIfNoReport);
        }

        /// <summary>
        /// Gets a scan report from an IP
        /// </summary>
        /// <param name="ip">The IP you wish to get the report on.</param>
        public Task<IPReport> GetIPReportAsync(string ip)
        {
            ip = ResourcesHelper.ValidateResourcea(ip, ResourceType.IP);

            return GetResult<IPReport>("ip-address/report?apikey=" + _defaultValues["apikey"] + "&ip=" + ip, HttpMethod.Get, null);
        }

        /// <summary>
        /// Gets a scan report from an IP
        /// </summary>
        /// <param name="ip">The IP you wish to get the report on.</param>
        public Task<IPReport> GetIPReportAsync(IPAddress ip)
        {
            return GetIPReportAsync(ip.ToString());
        }

        /// <summary>
        /// Gets a scan report from a domain
        /// </summary>
        /// <param name="domain">The domain you wish to get the report on.</param>
        public Task<DomainReport> GetDomainReportAsync(string domain)
        {
            domain = ResourcesHelper.ValidateResourcea(domain, ResourceType.Domain);

            //Hack because VT thought it was a good idea to have this API call as GET
            return GetResult<DomainReport>("domain/report?apikey=" + _defaultValues["apikey"] + "&domain=" + domain, HttpMethod.Get, null);
        }

        /// <summary>
        /// Gets a scan report from a domain
        /// </summary>
        /// <param name="domain">The domain you wish to get the report on.</param>
        public Task<DomainReport> GetDomainReportAsync(Uri domain)
        {
            return GetDomainReportAsync(domain.Host);
        }

        /// <summary>
        /// Retrieves a comment on a file.
        /// </summary>
        /// <param name="file">The file you wish to retrieve a comment from</param>
        /// <param name="before">TODO</param>
        public Task<CommentResult> GetCommentAsync(byte[] file, DateTime? before = null)
        {
            return GetCommentAsync(ResourcesHelper.GetResourceIdentifier(file), before);
        }

        /// <summary>
        /// Retrieves a comment on a file.
        /// </summary>
        /// <param name="file">The file you wish to retrieve a comment from</param>
        /// <param name="before">TODO</param>
        public Task<CommentResult> GetCommentAsync(FileInfo file, DateTime? before = null)
        {
            return GetCommentAsync(ResourcesHelper.GetResourceIdentifier(file), before);
        }

        /// <summary>
        /// Retrieves a comment from an URL.
        /// </summary>
        /// <param name="uri">The URL you wish to retrieve a comment from</param>
        /// <param name="before">TODO</param>
        public Task<CommentResult> GetCommentAsync(Uri uri, DateTime? before = null)
        {
            return GetCommentAsync(uri.ToString(), before);
        }

        /// <summary>
        /// Retrieves a comment on a resource.
        /// </summary>
        /// <param name="resource">The MD5/SHA1/SHA256 hash or URL.</param>
        /// <param name="before">TODO</param>
        public Task<CommentResult> GetCommentAsync(string resource, DateTime? before = null)
        {
            resource = ResourcesHelper.ValidateResourcea(resource, ResourceType.AnyHash | ResourceType.URL);

            //TODO: before

            //https://www.virustotal.com/vtapi/v2/comments/get
            return GetResult<CommentResult>("comments/get?apikey=" + _defaultValues["apikey"] + "&resource=" + resource, HttpMethod.Get, null);
        }

        /// <summary>
        /// Creates a comment on a file
        /// </summary>
        /// <param name="file">The file you wish to create a comment on</param>
        /// <param name="comment">The comment you wish to add.</param>
        public Task<CreateCommentResult> CreateCommentAsync(byte[] file, string comment)
        {
            return CreateCommentAsync(ResourcesHelper.GetResourceIdentifier(file), comment);
        }

        /// <summary>
        /// Creates a comment on a file
        /// </summary>
        /// <param name="file">The file you wish to create a comment on</param>
        /// <param name="comment">The comment you wish to add.</param>
        public Task<CreateCommentResult> CreateCommentAsync(FileInfo file, string comment)
        {
            return CreateCommentAsync(ResourcesHelper.GetResourceIdentifier(file), comment);
        }

        /// <summary>
        /// Creates a comment on an URL
        /// </summary>
        /// <param name="url">The URL you wish to create a comment on</param>
        /// <param name="comment">The comment you wish to add.</param>
        public Task<CreateCommentResult> CreateCommentAsync(Uri url, string comment)
        {
            return CreateCommentAsync(url.ToString(), comment);
        }

        /// <summary>
        /// Creates a comment on a resource
        /// </summary>
        /// <param name="resource">The MD5/SHA1/SHA256 hash or URL.</param>
        /// <param name="comment">The comment you wish to add.</param>
        public Task<CreateCommentResult> CreateCommentAsync(string resource, string comment)
        {
            resource = ResourcesHelper.ValidateResourcea(resource, ResourceType.AnyHash | ResourceType.URL);

            if (string.IsNullOrWhiteSpace(comment))
                throw new ArgumentException("Comment must not be null or whitespace", nameof(comment));

            if (RestrictSizeLimits && comment.Length > CommentSizeRestriction)
                throw new ArgumentOutOfRangeException(nameof(comment), $"Your comment is larger than the maximum size of {CommentSizeRestriction / 1024} KB");

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("resource", resource);
            values.Add("comment", comment);

            //https://www.virustotal.com/vtapi/v2/comments/put
            return GetResult<CreateCommentResult>("comments/put", HttpMethod.Post, CreateURLEncodedContent(values));
        }

        /// <summary>
        /// Gives you a link to a file analysis based on its hash.
        /// </summary>
        public string GetPublicFileScanLink(string resource)
        {
            resource = ResourcesHelper.ValidateResourcea(resource, ResourceType.AnyHash);

            return ResourcesHelper.NormalizeUrl($"www.virustotal.com/#/file/{resource}/detection", UseTLS);
        }

        /// <summary>
        /// Gives you a link to a file analysis based on its hash.
        /// Note: This actually hashes the file - if you have the hash already, use the overload that takes in a string.
        /// </summary>
        public string GetPublicFileScanLink(FileInfo file)
        {
            if (file == null)
                throw new ArgumentNullException(nameof(file));

            if (!file.Exists)
                throw new FileNotFoundException("The file you provided does not exist.", file.FullName);

            return GetPublicFileScanLink(ResourcesHelper.GetResourceIdentifier(file));
        }

        /// <summary>
        /// Gives you a link to a URL analysis.
        /// </summary>
        /// <returns>A link to VirusTotal that contains the report</returns>
        public string GetPublicUrlScanLink(string url)
        {
            url = ResourcesHelper.ValidateResourcea(url, ResourceType.URL);

            return ResourcesHelper.NormalizeUrl($"www.virustotal.com/#/url/{ResourcesHelper.GetResourceIdentifier(url)}/detection", UseTLS);
        }

        /// <summary>
        /// Gives you a link to a URL analysis.
        /// </summary>
        /// <returns>A link to VirusTotal that contains the report</returns>
        public string GetPublicUrlScanLink(Uri url)
        {
            return GetPublicUrlScanLink(url.ToString());
        }

        private async Task<IEnumerable<T>> GetResults<T>(string url, HttpMethod method, HttpContent content)
        {
            HttpResponseMessage response = await SendRequest(url, method, content).ConfigureAwait(false);

            using (Stream responseStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false))
            using (StreamReader sr = new StreamReader(responseStream, Encoding.UTF8))
            using (JsonTextReader jsonTextReader = new JsonTextReader(sr))
            {
                jsonTextReader.CloseInput = false;

                SaveResponse(responseStream);

                JToken token = JToken.Load(jsonTextReader);

                if (token.Type == JTokenType.Array)
                    return token.ToObject<List<T>>(_serializer);

                return new List<T> { token.ToObject<T>(_serializer) };
            }
        }

        private async Task<T> GetResult<T>(string url, HttpMethod method, HttpContent content)
        {
            HttpResponseMessage response = await SendRequest(url, method, content).ConfigureAwait(false);

            using (Stream responseStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false))
            using (StreamReader sr = new StreamReader(responseStream, Encoding.UTF8))
            using (JsonTextReader jsonTextReader = new JsonTextReader(sr))
            {
                jsonTextReader.CloseInput = false;

                SaveResponse(responseStream);

                return _serializer.Deserialize<T>(jsonTextReader);
            }
        }

        private async Task<HttpResponseMessage> SendRequest(string url, HttpMethod method, HttpContent content)
        {
            HttpRequestMessage request = new HttpRequestMessage(method, url);
            request.Content = content;

            OnHTTPRequestSending?.Invoke(request);

            HttpResponseMessage response = await _client.SendAsync(request).ConfigureAwait(false);

            OnHTTPResponseReceived?.Invoke(response);

            if (response.StatusCode == HttpStatusCode.NoContent)
                throw new RateLimitException("You have reached the 4 requests pr. min. limit of VirusTotal");

            if (response.StatusCode == HttpStatusCode.Forbidden)
                throw new AccessDeniedException("You don't have access to the service. Make sure your API key is working correctly.");

            if (response.StatusCode == HttpStatusCode.RequestEntityTooLarge)
                throw new SizeLimitException(FileSizeLimit);

            if (response.StatusCode != HttpStatusCode.OK)
                throw new Exception("API gave error code " + response.StatusCode);

            if (string.IsNullOrWhiteSpace(response.Content.ToString()))
                throw new Exception("There were no content in the response.");

            return response;
        }

        private void SaveResponse(Stream stream)
        {
            if (OnRawResponseReceived == null)
                return;

            using (MemoryStream ms = new MemoryStream())
            {
                stream.CopyTo(ms);
                OnRawResponseReceived(ms.ToArray());
            }

            stream.Position = 0;
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

        private HttpContent CreateFileContent(Stream stream, string fileName)
        {
            StreamContent fileContent = new StreamContent(stream);
            fileContent.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data")
            {
                Name = "\"file\"",
                FileName = "\"" + fileName + "\"",
                Size = stream.Length
            };
            fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            return fileContent;
        }

        private HttpContent CreateURLEncodedContent(IDictionary<string, string> values)
        {
            return new CustomURLEncodedContent(_defaultValues.Concat(values));
        }
    }
}