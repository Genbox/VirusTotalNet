using Newtonsoft.Json;
using VirusTotalNET.ResponseCodes;

namespace VirusTotalNET.Results
{
    public class ScanResult
    {
        /// <summary>
        /// MD5 hash of the resource.
        /// </summary>
        public string MD5 { get; set; }

        /// <summary>
        /// A unique link to this particular scan result.
        /// </summary>
        public string Permalink { get; set; }

        /// <summary>
        /// Id of the resource.
        /// </summary>
        public string Resource { get; set; }

        /// <summary>
        /// The unique scan id of the resource.
        /// </summary>
        [JsonProperty("scan_id")]
        public string ScanId { get; set; }

        /// <summary>
        /// SHA256 hash of the resource.
        /// </summary>
        public string SHA1 { get; set; }

        /// <summary>
        /// SHA256 hash of the resource.
        /// </summary>
        public string SHA256 { get; set; }

        [JsonProperty("response_code")]
        public ScanFileResponseCode ResponseCode { get; set; }

        /// <summary>
        /// Contains the message that corresponds to the response code.
        /// </summary>
        [JsonProperty("verbose_msg")]
        public string VerboseMsg { get; set; }
    }
}