using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.Serialization;
using System.Text.RegularExpressions;
using RestSharp;
using RestSharp.Deserializers;
using VirusTotalNET.Objects;

namespace VirusTotalNET
{
    public partial class VirusTotal
    {
        private static RestClient _client = new RestClient();
        private string _apiKey;
        private bool _useTls;
        private const long FileSizeLimit = 33554432; //32 MB
        private const int Retry = 3;
        private int _retryCounter = Retry;

        public VirusTotal(string apiKey)
        {
            if (string.IsNullOrEmpty(apiKey))
                throw new ArgumentException("the API key must not be empty.", "apiKey");

            _apiKey = apiKey;
            _client.BaseUrl = "http://www.virustotal.com/vtapi/v2/";
            _client.Proxy = null;
            _client.FollowRedirects = false;
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
                _client.BaseUrl = value ? _client.BaseUrl.Replace("http://", "https://") : _client.BaseUrl.Replace("https://", "http://");
            }
        }

        /// <summary>
        /// Scan a file. It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// </summary>
        /// <param name="file">The file to scan</param>
        /// <returns>The ScanResult object containing a SHA256 and ScanId.</returns>
        public ScanResult ScanFile(string file)
        {
            FileInfo fileInfo = new FileInfo(file);
            return ScanFile(fileInfo);
        }

        /// <summary>
        /// Scan a file. It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// </summary>
        /// <param name="file">The file to scan</param>
        /// <returns>The ScanResult object containing a SHA256 and ScanId.</returns>
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
        /// Tell VirusTotal to rescan a file without sending the actual file to VirusTotal.
        /// Before requesting a rescan you should retrieve the latest report on the files.
        /// </summary>
        /// <param name="resources">a MD5, SHA1, SHA256 of the file. You can also specify a CSV list made up of a combination of any of the three allowed hashes (up to 25 items), this allows you to perform a batch request with one single call. Note that the file must already be present in our file store.</param>
        /// <returns>A list of ScanResult objects containing the SHA256 and Scan ID of each item.</returns>
        public List<ScanResult> Rescan(params string[] resources)
        {
            if (resources.Length <= 0)
                throw new Exception("You have to supply a resource.");

            //https://www.virustotal.com/vtapi/v2/file/rescan
            RestRequest request = new RestRequest("file/rescan", Method.POST);

            //Required
            request.AddParameter("apikey", _apiKey);
            request.AddParameter("resource", string.Join(",", resources));

            //Output
            return GetResults<List<ScanResult>>(request);
        }

        /// <summary>
        /// Gets the report of the file.
        /// </summary>
        /// <param name="file">A list of files that will get hashes and scanned.</param>
        /// <returns></returns>
        public List<Report> GetFileReport(params FileInfo[] file)
        {
            string[] resources = new string[file.Length];

            for (int i = 0; i < file.Length; i++)
            {
                FileInfo fileInfo = file[i];
                if (fileInfo.Exists)
                    resources[i] = HashHelper.GetSHA256(fileInfo);
            }

            return GetFileReport(resources);
        }

        /// <summary>
        /// Gets the report of the file represented by its hash or scan ID.
        /// Keep in mind that URLs sent using the API have the lowest scanning priority, depending on VirusTotal's load, it may take several hours before the file is scanned,
        /// so query the report at regular intervals until the result shows up and do not keep submitting the file over and over again.
        /// </summary>
        /// <param name="resources">SHA1, MD5 or SHA256 of the file. It can also be a scan ID of a previous scan.</param>
        /// <returns></returns>
        public List<Report> GetFileReport(params string[] resources)
        {
            if (resources.Length <= 0)
                throw new Exception("You have to supply a resource.");

            //https://www.virustotal.com/vtapi/v2/file/report
            RestRequest request = new RestRequest("file/report", Method.POST);

            //Required
            request.AddParameter("apikey", _apiKey);
            request.AddParameter("resource", string.Join(",", resources));

            //Output
            return GetResults<List<Report>>(request, true);
        }

        /// <summary>
        /// Scan the given URL. The file will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest report on the URL.
        /// </summary>
        /// <param name="url">The url to process. You can give multiple URLs to scan in bulk.</param>
        /// <returns>A list of ScanResult objects with SHA256 and scan ID of each item.</returns>
        public List<ScanResult> ScanUrl(params string[] url)
        {
            if (url.Length <= 0)
                throw new Exception("You have to supply an URL.");

            //https://www.virustotal.com/vtapi/v2/url/scan
            RestRequest request = new RestRequest("url/scan", Method.POST);

            //Required
            request.AddParameter("apikey", _apiKey);
            request.AddParameter("url", string.Join(",", url));

            //Output
            return GetResults<List<ScanResult>>(request);
        }

        /// <summary>
        /// Get a scan report from an URL
        /// </summary>
        /// <param name="url">The URL the report represents. Note that you can specify multiple URLs to scan URLs in bulk.</param>
        /// <returns>A list of Report objects that contain various hashes and scan ID of each item.</returns>
        public List<Report> GetUrlReport(params string[] url)
        {
            if (url.Length <= 0)
                throw new Exception("You have to supply an URL.");

            RestRequest request = new RestRequest("url/report", Method.POST);

            //Required
            request.AddParameter("apikey", _apiKey);
            request.AddParameter("resource", string.Join(",", url));

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
            if (string.IsNullOrEmpty(resource))
                throw new ArgumentException("Resource must not be null or empty", "resource");

            if (string.IsNullOrEmpty(comment))
                throw new ArgumentException("Comment must not be null or empty", "comment");

            //https://www.virustotal.com/vtapi/v2/comments/put
            RestRequest request = new RestRequest("comments/put", Method.POST);

            //Required
            request.AddParameter("apikey", _apiKey);
            request.AddParameter("resource", resource);
            request.AddParameter("comment", comment);

            //Output
            return GetResults<ScanResult>(request);
        }

        public string GetPublicScanLink(FileInfo file)
        {
            return string.Format("{0}://www.virustotal.com/file/{1}/analysis/", UseTLS ? "https" : "http", HashHelper.GetSHA256(file));
        }

        public string GetPublicScanLink(string url)
        {
            return string.Format("{0}://www.virustotal.com/url/{1}/analysis/", UseTLS ? "https" : "http", HashHelper.GetSHA256(NormalizeUrl(url)));
        }

        private T GetResults<T>(RestRequest request, bool applyHack = false)
        {
            RestResponse response = (RestResponse)_client.Execute(request);

            if (response.StatusCode == HttpStatusCode.NoContent)
                throw new RateLimitException("You have reached the 5 requests pr. min. limit of VirusTotal");

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
    }
}