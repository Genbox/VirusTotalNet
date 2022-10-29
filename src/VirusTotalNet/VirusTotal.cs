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
using VirusTotalNet.Enums;
using VirusTotalNet.Exceptions;
using VirusTotalNet.Helpers;
using VirusTotalNet.Internal.Objects;
using VirusTotalNet.Internal.Other;
using VirusTotalNet.Results;

namespace VirusTotalNet;

public class VirusTotal
{
    private readonly HttpClient _client;
    private readonly HttpClientHandler _httpClientHandler;
    private readonly JsonSerializer _serializer;
    private readonly string _defaultApiUrl = "www.virustotal.com/vtapi/v2/";
    private readonly string _apiUrl;
    private readonly string _apiKey;

    /// <param name="apiKey">The API key you got from Virus Total</param>
    /// <param name="apiUrl">An optional url for a different API endpoint</param>
    public VirusTotal(string apiKey, string apiUrl = null)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
            throw new ArgumentException("You have to set an API key.", nameof(apiKey));

        if (apiKey.Length < 64)
            throw new ArgumentException("API key is too short.", nameof(apiKey));

        _apiKey = apiKey;
        _apiUrl = apiUrl ?? _defaultApiUrl;

        _httpClientHandler = new HttpClientHandler();
        _httpClientHandler.AllowAutoRedirect = true;
        _client = new HttpClient(_httpClientHandler);

        JsonSerializerSettings jsonSettings = new JsonSerializerSettings();
        jsonSettings.NullValueHandling = NullValueHandling.Ignore;
        jsonSettings.Formatting = Formatting.None;

        _serializer = JsonSerializer.Create(jsonSettings);

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
    public int FileSizeLimit { get; set; } = 33553369; //32 MB - 1063 = 33553369 it is the effective limit by virus total as it measures file size limit on the TOTAL request size, and not just the file content.

    /// <summary>
    /// The maximum size when using the large file API functionality (part of private API)
    /// </summary>
    public long LargeFileSizeLimit { get; set; } = 1024 * 1024 * 200; //200 MB

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
    public bool UseTLS { get; set; } = true;

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
        set
        {
            _httpClientHandler.UseProxy = value != null;
            _httpClientHandler.Proxy = value;
        }
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
    /// Scan a file.
    /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
    /// </summary>
    /// <param name="filePath">The file to scan</param>
    public async Task<ScanResult> ScanFileAsync(string filePath)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException("The file was not found.", filePath);

        string filename = Path.GetFileName(filePath);

        using Stream fs = File.OpenRead(filePath);
        return await ScanFileAsync(fs, filename).ConfigureAwait(false);
    }

    /// <summary>
    /// Scan a file.
    /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
    /// </summary>
    /// <param name="file">The file to scan</param>
    public async Task<ScanResult> ScanFileAsync(FileInfo file)
    {
        if (!file.Exists)
            throw new FileNotFoundException("The file was not found.", file.Name);

        using Stream fs = file.OpenRead();
        return await ScanFileAsync(fs, file.Name).ConfigureAwait(false);
    }

    /// <summary>
    /// Scan a file.
    /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
    /// Note: You are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
    /// </summary>
    /// <param name="file">The file to scan</param>
    /// <param name="filename">The filename of the file</param>
    public async Task<ScanResult> ScanFileAsync(byte[] file, string filename)
    {
        using MemoryStream ms = new MemoryStream(file);
        return await ScanFileAsync(ms, filename).ConfigureAwait(false);
    }

    /// <summary>
    /// Scan a file.
    /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
    /// Note: You are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
    /// </summary>
    /// <param name="stream">The file to scan</param>
    /// <param name="filename">The filename of the file</param>
    public async Task<ScanResult> ScanFileAsync(Stream stream, string filename)
    {
        ValidateScanFileArguments(stream, FileSizeLimit, filename);

        using MultipartFormDataContent multi = new MultipartFormDataContent();
        multi.Add(CreateApiPart());
        multi.Add(CreateFileContent(stream, filename));

        //https://www.virustotal.com/vtapi/v2/file/scan
        return await GetResponse<ScanResult>("file/scan", HttpMethod.Post, multi).ConfigureAwait(false);
    }

    /// <summary>
    /// Scan a large file. The difference between <see cref="ScanFileAsync(FileInfo)"/> and this method, is that this method sends 2 requests, and it is part of the private VT API, so you need an API key with large file upload support.
    /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
    /// </summary>
    /// <param name="filePath">The file to scan</param>
    public async Task<ScanResult> ScanLargeFileAsync(string filePath)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException("The file was not found.", filePath);

        string filename = Path.GetFileName(filePath);

        using Stream fs = File.OpenRead(filePath);
        return await ScanLargeFileAsync(fs, filename).ConfigureAwait(false);
    }

    /// <summary>
    /// Scan a large file. The difference between <see cref="ScanFileAsync(FileInfo)"/> and this method, is that this method sends 2 requests, and it is part of the private VT API, so you need an API key with large file upload support.
    /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
    /// </summary>
    /// <param name="file">The file to scan</param>
    public async Task<ScanResult> ScanLargeFileAsync(FileInfo file)
    {
        if (!file.Exists)
            throw new FileNotFoundException("The file was not found.", file.Name);

        using Stream fs = file.OpenRead();
        return await ScanLargeFileAsync(fs, file.Name).ConfigureAwait(false);
    }

    /// <summary>
    /// Scan a large file. The difference between <see cref="ScanFileAsync(FileInfo)"/> and this method, is that this method sends 2 requests, and it is part of the private VT API, so you need an API key with large file upload support.
    /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
    /// Note: You are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
    /// </summary>
    /// <param name="file">The file to scan</param>
    /// <param name="filename">The filename of the file</param>
    public async Task<ScanResult> ScanLargeFileAsync(byte[] file, string filename)
    {
        using MemoryStream ms = new MemoryStream(file);
        return await ScanLargeFileAsync(ms, filename).ConfigureAwait(false);
    }

    /// <summary>
    /// Scan a large file. The difference between <see cref="ScanFileAsync(FileInfo)"/> and this method, is that this method sends 2 requests, and it is part of the private VT API, so you need an API key with large file upload support.
    /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
    /// Note: You are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
    /// </summary>
    /// <param name="stream">The file to scan</param>
    /// <param name="filename">The filename of the file</param>
    public async Task<ScanResult> ScanLargeFileAsync(Stream stream, string filename)
    {
        ValidateScanFileArguments(stream, LargeFileSizeLimit, filename);

        if (stream.Length <= FileSizeLimit)
            throw new ArgumentException($"Please use the ScanFileAsync() method for files smaller than {FileSizeLimit} bytes");

        //https://www.virustotal.com/vtapi/v2/file/scan/upload_url
        LargeFileUpload uploadUrlObj = await GetResponse<LargeFileUpload>("file/scan/upload_url?apikey=" + _defaultValues["apikey"], HttpMethod.Get, null).ConfigureAwait(false);

        if (string.IsNullOrEmpty(uploadUrlObj.UploadUrl))
            throw new Exception("Something when wrong while getting the upload url. Are you using an API key with support for this request?");

        using MultipartFormDataContent multi = new MultipartFormDataContent();
        multi.Add(CreateFileContent(stream, filename, false)); //The big file upload API does not like it when multi-part uploads contain the size field

        return await GetResponse<ScanResult>(uploadUrlObj.UploadUrl, HttpMethod.Post, multi).ConfigureAwait(false);
    }

    private void ValidateScanFileArguments(Stream stream, long fileSizeLimit, string filename)
    {
        if (stream == null)
            throw new ArgumentNullException(nameof(stream), "You must provide a stream that is not null");

        if (stream.Length <= 0)
            throw new ArgumentException("You must provide a stream with content", nameof(stream));

        if (RestrictSizeLimits && stream.Length > fileSizeLimit)
            throw new SizeLimitException(fileSizeLimit, stream.Length);

        if (string.IsNullOrWhiteSpace(filename))
            throw new ArgumentException("You must provide a filename. Preferably the original filename.");
    }

    /// <summary>
    /// Tell VirusTotal to rescan a file.
    /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
    /// Note: Before requesting a rescan you should retrieve the latest report on the file.
    /// </summary>
    public async Task<RescanResult> RescanFileAsync(FileInfo file)
    {
        return await RescanFileAsync(ResourcesHelper.GetResourceIdentifier(file)).ConfigureAwait(false);
    }

    /// <summary>
    /// Tell VirusTotal to rescan a file.
    /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
    /// Note: Before requesting a rescan you should retrieve the latest report on the file.
    /// </summary>
    public async Task<RescanResult> RescanFileAsync(byte[] file)
    {
        return await RescanFileAsync(ResourcesHelper.GetResourceIdentifier(file)).ConfigureAwait(false);
    }

    /// <summary>
    /// Tell VirusTotal to rescan a file.
    /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
    /// Note: Before requesting a rescan you should retrieve the latest report on the file.
    /// </summary>
    public async Task<RescanResult> RescanFileAsync(Stream stream)
    {
        return await RescanFileAsync(ResourcesHelper.GetResourceIdentifier(stream)).ConfigureAwait(false);
    }

    /// <summary>
    /// Tell VirusTotal to rescan a file without sending the actual file to VirusTotal.
    /// Note: Before requesting a rescan you should retrieve the latest report on the file.
    /// </summary>
    /// <param name="resource">A hash of the file. It can be an MD5, SHA1 or SHA256</param>
    public async Task<RescanResult> RescanFileAsync(string resource)
    {
        resource = ResourcesHelper.ValidateResourcea(resource, ResourceType.AnyHash);

        //Required
        Dictionary<string, string> values = new Dictionary<string, string>(2, StringComparer.OrdinalIgnoreCase);
        values.Add("resource", resource);

        //https://www.virustotal.com/vtapi/v2/file/rescan
        return await GetResponse<RescanResult>("file/rescan", HttpMethod.Post, CreateUrlEncodedContent(values)).ConfigureAwait(false);
    }

    /// <summary>
    /// Tell VirusTotal to rescan a file.
    /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
    /// Note: Before requesting a rescan you should retrieve the latest report on the files.
    /// </summary>
    public async Task<IEnumerable<RescanResult>> RescanFilesAsync(IEnumerable<FileInfo> files)
    {
        return await RescanFilesAsync(ResourcesHelper.GetResourceIdentifier(files)).ConfigureAwait(false);
    }

    /// <summary>
    /// Tell VirusTotal to rescan a file.
    /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
    /// Note: Before requesting a rescan you should retrieve the latest report on the files.
    /// </summary>
    public async Task<IEnumerable<RescanResult>> RescanFilesAsync(IEnumerable<byte[]> files)
    {
        return await RescanFilesAsync(ResourcesHelper.GetResourceIdentifier(files)).ConfigureAwait(false);
    }

    /// <summary>
    /// Tell VirusTotal to rescan a file.
    /// Note: This does not send the content of the streams to VirusTotal. It hashes the content and sends that instead.
    /// Note: Before requesting a rescan you should retrieve the latest report on the files.
    /// </summary>
    public async Task<IEnumerable<RescanResult>> RescanFilesAsync(IEnumerable<Stream> streams)
    {
        return await RescanFilesAsync(ResourcesHelper.GetResourceIdentifier(streams)).ConfigureAwait(false);
    }

    /// <summary>
    /// Tell VirusTotal to rescan a file.
    /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
    /// Note: Before requesting a rescan you should retrieve the latest report on the files.
    /// Note: You can use MD5, SHA1 or SHA256 and even mix them.
    /// Note: You can only request a maximum of 25 rescans at the time.
    /// </summary>
    /// <param name="resourceList">a MD5, SHA1 or SHA256 of the files. You can also specify list made up of a combination of any of the three allowed hashes (up to 25 items), this allows you to perform a batch request with one single call.</param>
    public async Task<IEnumerable<RescanResult>> RescanFilesAsync(IEnumerable<string> resourceList)
    {
        resourceList = ResourcesHelper.ValidateResourcea(resourceList, ResourceType.AnyHash);

        string[] resources = resourceList as string[] ?? resourceList.ToArray();

        if (RestrictNumberOfResources && resources.Length > RescanBatchSizeLimit)
            throw new ResourceLimitException($"Too many resources. There is a maximum of {RescanBatchSizeLimit} resources at the time.");

        //Required
        Dictionary<string, string> values = new Dictionary<string, string>(2, StringComparer.OrdinalIgnoreCase);
        values.Add("resource", string.Join(",", resources));

        //https://www.virustotal.com/vtapi/v2/file/rescan
        return await GetResponses<RescanResult>("file/rescan", HttpMethod.Post, CreateUrlEncodedContent(values)).ConfigureAwait(false);
    }

    /// <summary>
    /// Gets the report of the file.
    /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
    /// </summary>
    /// <param name="file">The file you want to get a report on.</param>
    public async Task<FileReport> GetFileReportAsync(byte[] file)
    {
        return await GetFileReportAsync(ResourcesHelper.GetResourceIdentifier(file)).ConfigureAwait(false);
    }

    /// <summary>
    /// Gets the report of the file.
    /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
    /// </summary>
    /// <param name="file">The file you want to get a report on.</param>
    public async Task<FileReport> GetFileReportAsync(FileInfo file)
    {
        return await GetFileReportAsync(ResourcesHelper.GetResourceIdentifier(file)).ConfigureAwait(false);
    }

    /// <summary>
    /// Gets the report of the file.
    /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
    /// </summary>
    /// <param name="stream">The stream you want to get a report on.</param>
    public async Task<FileReport> GetFileReportAsync(Stream stream)
    {
        return await GetFileReportAsync(ResourcesHelper.GetResourceIdentifier(stream)).ConfigureAwait(false);
    }

    /// <summary>
    /// Gets the report of the file.
    /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
    /// </summary>
    /// <param name="resource">The resource (MD5, SHA1 or SHA256) you wish to get a report on.</param>
    public async Task<FileReport> GetFileReportAsync(string resource)
    {
        resource = ResourcesHelper.ValidateResourcea(resource, ResourceType.AnyHash | ResourceType.ScanId);

        //Required
        Dictionary<string, string> values = new Dictionary<string, string>(2, StringComparer.OrdinalIgnoreCase);
        values.Add("resource", resource);

        //https://www.virustotal.com/vtapi/v2/file/report
        return await GetResponse<FileReport>("file/report", HttpMethod.Post, CreateUrlEncodedContent(values)).ConfigureAwait(false);
    }

    /// <summary>
    /// Gets a list of reports of the files.
    /// Note: This does not send the files to VirusTotal. It hashes the files and sends them instead.
    /// </summary>
    /// <param name="files">The files you want to get reports on.</param>
    public async Task<IEnumerable<FileReport>> GetFileReportsAsync(IEnumerable<byte[]> files)
    {
        return await GetFileReportsAsync(ResourcesHelper.GetResourceIdentifier(files)).ConfigureAwait(false);
    }

    /// <summary>
    /// Gets a list of reports of the files.
    /// Note: This does not send the files to VirusTotal. It hashes the files and sends them instead.
    /// </summary>
    /// <param name="files">The files you want to get reports on.</param>
    public async Task<IEnumerable<FileReport>> GetFileReportsAsync(IEnumerable<FileInfo> files)
    {
        return await GetFileReportsAsync(ResourcesHelper.GetResourceIdentifier(files)).ConfigureAwait(false);
    }

    /// <summary>
    /// Gets a list of reports of the files.
    /// Note: This does not send the content of the streams to VirusTotal. It hashes the content of the stream and sends that instead.
    /// </summary>
    /// <param name="streams">The streams you want to get reports on.</param>
    public async Task<IEnumerable<FileReport>> GetFileReportsAsync(IEnumerable<Stream> streams)
    {
        return await GetFileReportsAsync(ResourcesHelper.GetResourceIdentifier(streams)).ConfigureAwait(false);
    }

    /// <summary>
    /// Gets the report of the file represented by its hash or scan ID.
    /// Keep in mind that URLs sent using the API have the lowest scanning priority, depending on VirusTotal's load, it may take several hours before the file is scanned,
    /// so query the report at regular intervals until the result shows up and do not keep submitting the file over and over again.
    /// </summary>
    /// <param name="resourceList">SHA1, MD5 or SHA256 of the file. It can also be a scan ID of a previous scan.</param>
    public async Task<IEnumerable<FileReport>> GetFileReportsAsync(IEnumerable<string> resourceList)
    {
        resourceList = ResourcesHelper.ValidateResourcea(resourceList, ResourceType.AnyHash | ResourceType.ScanId);

        string[] resources = resourceList as string[] ?? resourceList.ToArray();

        if (RestrictNumberOfResources && resources.Length > FileReportBatchSizeLimit)
            throw new ResourceLimitException($"Too many hashes. There is a maximum of {FileReportBatchSizeLimit} resources at the same time.");

        //Required
        Dictionary<string, string> values = new Dictionary<string, string>(2, StringComparer.OrdinalIgnoreCase);
        values.Add("resource", string.Join(",", resources));

        //https://www.virustotal.com/vtapi/v2/file/report
        return await GetResponses<FileReport>("file/report", HttpMethod.Post, CreateUrlEncodedContent(values)).ConfigureAwait(false);
    }

    /// <summary>
    /// Scan the given URL. The URL will be downloaded by VirusTotal and processed.
    /// Note: Before performing your submission, you should retrieve the latest report on the URL.
    /// </summary>
    /// <param name="url">The URL to process.</param>
    public async Task<UrlScanResult> ScanUrlAsync(string url)
    {
        url = ResourcesHelper.ValidateResourcea(url, ResourceType.URL);

        //Required
        Dictionary<string, string> values = new Dictionary<string, string>(2, StringComparer.OrdinalIgnoreCase);
        values.Add("url", url);

        //https://www.virustotal.com/vtapi/v2/url/scan
        return await GetResponse<UrlScanResult>("url/scan", HttpMethod.Post, CreateUrlEncodedContent(values)).ConfigureAwait(false);
    }

    /// <summary>
    /// Scan the given URL. The URL will be downloaded by VirusTotal and processed.
    /// Note: Before performing your submission, you should retrieve the latest report on the URL.
    /// </summary>
    /// <param name="url">The URL to process.</param>
    public async Task<UrlScanResult> ScanUrlAsync(Uri url)
    {
        return await ScanUrlAsync(url.ToString()).ConfigureAwait(false);
    }

    /// <summary>
    /// Scan the given URLs. The URLs will be downloaded by VirusTotal and processed.
    /// Note: Before performing your submission, you should retrieve the latest reports on the URLs.
    /// </summary>
    /// <param name="urls">The URLs to process.</param>
    public async Task<IEnumerable<UrlScanResult>> ScanUrlsAsync(IEnumerable<string> urls)
    {
        urls = ResourcesHelper.ValidateResourcea(urls, ResourceType.URL);

        string[] urlCast = urls as string[] ?? urls.ToArray();

        if (RestrictNumberOfResources && urlCast.Length > UrlScanBatchSizeLimit)
            throw new ResourceLimitException($"Too many URLs. There is a maximum of {UrlScanBatchSizeLimit} URLs at the same time.");

        //Required
        Dictionary<string, string> values = new Dictionary<string, string>(2, StringComparer.OrdinalIgnoreCase);
        values.Add("url", string.Join(Environment.NewLine, urlCast));

        //https://www.virustotal.com/vtapi/v2/url/scan
        return await GetResponses<UrlScanResult>("url/scan", HttpMethod.Post, CreateUrlEncodedContent(values)).ConfigureAwait(false);
    }

    /// <summary>
    /// Scan the given URLs. The URLs will be downloaded by VirusTotal and processed.
    /// Note: Before performing your submission, you should retrieve the latest reports on the URLs.
    /// </summary>
    /// <param name="urlList">The URLs to process.</param>
    public async Task<IEnumerable<UrlScanResult>> ScanUrlsAsync(IEnumerable<Uri> urlList)
    {
        return await ScanUrlsAsync(urlList.Select(x => x.ToString())).ConfigureAwait(false);
    }

    /// <summary>
    /// Gets a scan report from an URL
    /// </summary>
    /// <param name="url">The URL you wish to get the report on.</param>
    /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URL if it is not present in the database.</param>
    public async Task<UrlReport> GetUrlReportAsync(string url, bool scanIfNoReport = false)
    {
        url = ResourcesHelper.ValidateResourcea(url, ResourceType.URL | ResourceType.ScanId);

        //Required
        Dictionary<string, string> values = new Dictionary<string, string>(3, StringComparer.OrdinalIgnoreCase);
        values.Add("resource", url);

        //Optional
        if (scanIfNoReport)
            values.Add("scan", "1");

        //Output
        return await GetResponse<UrlReport>("url/report", HttpMethod.Post, CreateUrlEncodedContent(values)).ConfigureAwait(false);
    }

    /// <summary>
    /// Gets a scan report from an URL
    /// </summary>
    /// <param name="url">The URL you wish to get the report on.</param>
    /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URL if it is not present in the database.</param>
    public async Task<UrlReport> GetUrlReportAsync(Uri url, bool scanIfNoReport = false)
    {
        return await GetUrlReportAsync(url.ToString(), scanIfNoReport).ConfigureAwait(false);
    }

    /// <summary>
    /// Gets a scan report from a list of URLs
    /// </summary>
    /// <param name="urls">The URLs you wish to get the reports on.</param>
    /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URLs if it is not present in the database.</param>
    public async Task<IEnumerable<UrlReport>> GetUrlReportsAsync(IEnumerable<string> urls, bool scanIfNoReport = false)
    {
        urls = ResourcesHelper.ValidateResourcea(urls, ResourceType.URL | ResourceType.ScanId);

        string[] urlCast = urls as string[] ?? urls.ToArray();

        if (RestrictNumberOfResources && urlCast.Length > UrlReportBatchSizeLimit)
            throw new ResourceLimitException($"Too many URLs. There is a maximum of {UrlReportBatchSizeLimit} urls at the time.");

        //Required
        Dictionary<string, string> values = new Dictionary<string, string>(3, StringComparer.OrdinalIgnoreCase);
        values.Add("resource", string.Join(Environment.NewLine, urlCast));

        //Optional
        if (scanIfNoReport)
            values.Add("scan", "1");

        //Output
        return await GetResponses<UrlReport>("url/report", HttpMethod.Post, CreateUrlEncodedContent(values)).ConfigureAwait(false);
    }

    /// <summary>
    /// Gets a scan report from a list of URLs
    /// </summary>
    /// <param name="urlList">The URLs you wish to get the reports on.</param>
    /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URLs if it is not present in the database.</param>
    public async Task<IEnumerable<UrlReport>> GetUrlReportsAsync(IEnumerable<Uri> urlList, bool scanIfNoReport = false)
    {
        return await GetUrlReportsAsync(urlList.Select(x => x.ToString()), scanIfNoReport).ConfigureAwait(false);
    }

    /// <summary>
    /// Gets a scan report from an IP
    /// </summary>
    /// <param name="ip">The IP you wish to get the report on.</param>
    public async Task<IPReport> GetIPReportAsync(string ip)
    {
        ip = ResourcesHelper.ValidateResourcea(ip, ResourceType.IP);

        return await GetResponse<IPReport>($"ip-address/report?apikey={_apiKey}&ip={ip}", HttpMethod.Get, null).ConfigureAwait(false);
    }

    /// <summary>
    /// Gets a scan report from an IP
    /// </summary>
    /// <param name="ip">The IP you wish to get the report on.</param>
    public async Task<IPReport> GetIPReportAsync(IPAddress ip)
    {
        return await GetIPReportAsync(ip.ToString()).ConfigureAwait(false);
    }

    /// <summary>
    /// Gets a scan report from a domain
    /// </summary>
    /// <param name="domain">The domain you wish to get the report on.</param>
    public async Task<DomainReport> GetDomainReportAsync(string domain)
    {
        domain = ResourcesHelper.ValidateResourcea(domain, ResourceType.Domain);

        //Hack because VT thought it was a good idea to have this API call as GET
        return await GetResponse<DomainReport>($"domain/report?apikey={_apiKey}&domain={domain}", HttpMethod.Get, null).ConfigureAwait(false);
    }

    /// <summary>
    /// Gets a scan report from a domain
    /// </summary>
    /// <param name="domain">The domain you wish to get the report on.</param>
    public async Task<DomainReport> GetDomainReportAsync(Uri domain)
    {
        return await GetDomainReportAsync(domain.Host).ConfigureAwait(false);
    }

    /// <summary>
    /// Retrieves a comment on a file.
    /// </summary>
    /// <param name="file">The file you wish to retrieve a comment from</param>
    /// <param name="before">TODO</param>
    public async Task<CommentResult> GetCommentAsync(byte[] file, DateTime? before = null)
    {
        return await GetCommentAsync(ResourcesHelper.GetResourceIdentifier(file), before).ConfigureAwait(false);
    }

    /// <summary>
    /// Retrieves a comment on a file.
    /// </summary>
    /// <param name="file">The file you wish to retrieve a comment from</param>
    /// <param name="before">TODO</param>
    public async Task<CommentResult> GetCommentAsync(FileInfo file, DateTime? before = null)
    {
        return await GetCommentAsync(ResourcesHelper.GetResourceIdentifier(file), before).ConfigureAwait(false);
    }

    /// <summary>
    /// Retrieves a comment from an URL.
    /// </summary>
    /// <param name="uri">The URL you wish to retrieve a comment from</param>
    /// <param name="before">TODO</param>
    public async Task<CommentResult> GetCommentAsync(Uri uri, DateTime? before = null)
    {
        return await GetCommentAsync(uri.ToString(), before).ConfigureAwait(false);
    }

    /// <summary>
    /// Retrieves a comment on a resource.
    /// </summary>
    /// <param name="resource">The MD5/SHA1/SHA256 hash or URL.</param>
    /// <param name="before">TODO</param>
    public async Task<CommentResult> GetCommentAsync(string resource, DateTime? before = null)
    {
        resource = ResourcesHelper.ValidateResourcea(resource, ResourceType.AnyHash | ResourceType.URL);

        //TODO: before

        //https://www.virustotal.com/vtapi/v2/comments/get
        return await GetResponse<CommentResult>($"comments/get?apikey={_apiKey}&resource={resource}", HttpMethod.Get, null).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates a comment on a file
    /// </summary>
    /// <param name="file">The file you wish to create a comment on</param>
    /// <param name="comment">The comment you wish to add.</param>
    public async Task<CreateCommentResult> CreateCommentAsync(byte[] file, string comment)
    {
        return await CreateCommentAsync(ResourcesHelper.GetResourceIdentifier(file), comment).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates a comment on a file
    /// </summary>
    /// <param name="file">The file you wish to create a comment on</param>
    /// <param name="comment">The comment you wish to add.</param>
    public async Task<CreateCommentResult> CreateCommentAsync(FileInfo file, string comment)
    {
        return await CreateCommentAsync(ResourcesHelper.GetResourceIdentifier(file), comment).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates a comment on an URL
    /// </summary>
    /// <param name="url">The URL you wish to create a comment on</param>
    /// <param name="comment">The comment you wish to add.</param>
    public async Task<CreateCommentResult> CreateCommentAsync(Uri url, string comment)
    {
        return await CreateCommentAsync(url.ToString(), comment).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates a comment on a resource
    /// </summary>
    /// <param name="resource">The MD5/SHA1/SHA256 hash or URL.</param>
    /// <param name="comment">The comment you wish to add.</param>
    public async Task<CreateCommentResult> CreateCommentAsync(string resource, string comment)
    {
        resource = ResourcesHelper.ValidateResourcea(resource, ResourceType.AnyHash | ResourceType.URL);

        if (string.IsNullOrWhiteSpace(comment))
            throw new ArgumentException("Comment must not be null or whitespace", nameof(comment));

        if (RestrictSizeLimits && comment.Length > CommentSizeRestriction)
            throw new ArgumentOutOfRangeException(nameof(comment), $"Your comment is larger than the maximum size of {CommentSizeRestriction / 1024} KB");

        //Required
        Dictionary<string, string> values = new Dictionary<string, string>(3, StringComparer.OrdinalIgnoreCase);
        values.Add("resource", resource);
        values.Add("comment", comment);

        //https://www.virustotal.com/vtapi/v2/comments/put
        return await GetResponse<CreateCommentResult>("comments/put", HttpMethod.Post, CreateUrlEncodedContent(values)).ConfigureAwait(false);
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

    private async Task<IEnumerable<T>> GetResponses<T>(string url, HttpMethod method, HttpContent content)
    {
        using HttpResponseMessage response = await SendRequest(url, method, content).ConfigureAwait(false);

        using (Stream responseStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false))
        using (StreamReader sr = new StreamReader(responseStream, Encoding.UTF8))
        using (JsonTextReader jsonTextReader = new JsonTextReader(sr))
        {
            jsonTextReader.CloseInput = false;

            SaveResponse(responseStream);

            JToken token = await JToken.LoadAsync(jsonTextReader).ConfigureAwait(false);

            if (token.Type == JTokenType.Array)
                return token.ToObject<List<T>>(_serializer);

            return new List<T> { token.ToObject<T>(_serializer) };
        }
    }

    private async Task<T> GetResponse<T>(string url, HttpMethod method, HttpContent content)
    {
        using HttpResponseMessage response = await SendRequest(url, method, content).ConfigureAwait(false);

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
        //We need this check because sometimes url is a full url and sometimes it is just an url segment
        if (!url.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            url = (UseTLS ? "https://" : "http://") + _apiUrl + url;

        using HttpRequestMessage request = new HttpRequestMessage(method, url);
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
        HttpContent content = new StringContent(_apiKey);
        content.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data")
        {
            Name = "\"apikey\""
        };

        return content;
    }

    private HttpContent CreateFileContent(Stream stream, string fileName, bool includeSize = true)
    {
        StreamContent fileContent = new StreamContent(stream);

        ContentDispositionHeaderValue disposition = new ContentDispositionHeaderValue("form-data");
        disposition.Name = "\"file\"";
        disposition.FileName = "\"" + fileName + "\"";

        if (includeSize)
            disposition.Size = stream.Length;

        fileContent.Headers.ContentDisposition = disposition;
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        return fileContent;
    }

    private HttpContent CreateUrlEncodedContent(Dictionary<string, string> values)
    {
        values.Add("apikey", _apiKey);
        return new CustomURLEncodedContent(values);
    }
}