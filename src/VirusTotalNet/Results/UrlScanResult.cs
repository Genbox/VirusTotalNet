using System;
using Newtonsoft.Json;
using VirusTotalNet.ResponseCodes;

namespace VirusTotalNet.Results;

public class UrlScanResult
{
    public string Url { get; set; }

    [JsonProperty("scan_date")]
    public DateTime ScanDate { get; set; }

    /// <summary>
    /// A unique link to this particular scan result.
    /// </summary>
    public string Permalink { get; set; }

    /// <summary>
    /// The resource.
    /// </summary>
    public string Resource { get; set; }

    /// <summary>
    /// The unique scan id of the resource.
    /// </summary>
    [JsonProperty("scan_id")]
    public string ScanId { get; set; }

    [JsonProperty("response_code")]
    public UrlScanResponseCode ResponseCode { get; set; }

    /// <summary>
    /// Contains the message that corresponds to the response code.
    /// </summary>
    [JsonProperty("verbose_msg")]
    public string VerboseMsg { get; set; }
}