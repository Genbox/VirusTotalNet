using Newtonsoft.Json;
using VirusTotalNet.ResponseCodes;

namespace VirusTotalNet.Results
{
    public class RescanResult
    {
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
        public string SHA256 { get; set; }

        [JsonProperty("response_code")]
        public RescanResponseCode ResponseCode { get; set; }
    }
}