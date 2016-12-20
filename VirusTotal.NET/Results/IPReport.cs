using System.Collections.Generic;
using Newtonsoft.Json;
using VirusTotalNET.Objects;
using VirusTotalNET.ResponseCodes;

namespace VirusTotalNET.Results
{
    public class IPReport
    {
        [JsonProperty("as_owner")]
        public string AsOwner { get; set; }

        public int ASN { get; set; }

        public string Country { get; set; }

        [JsonProperty("detected_communicating_samples")]
        public List<Sample> DetectedCommunicatingSamples { get; set; }

        [JsonProperty("detected_downloaded_samples")]
        public List<Sample> DetectedDownloadedSamples { get; set; }

        [JsonProperty("detected_referrer_samples")]
        public List<Sample> DetectedReferrerSamples { get; set; }

        [JsonProperty("detected_urls")]
        public List<DetectedUrl> DetectedUrls { get; set; }

        public List<Resolution> Resolutions { get; set; }

        [JsonProperty("undetected_communicating_samples")]
        public List<Sample> UndetectedCommunicatingSamples { get; set; }

        [JsonProperty("undetected_downloaded_samples")]
        public List<Sample> UndetectedDownloadedSamples { get; set; }

        [JsonProperty("undetected_referrer_samples")]
        public List<Sample> undetectedReferrerSamples { get; set; }

        /// <summary>
        /// The response code. Use this to determine the status of the report.
        /// </summary>
        [JsonProperty("response_code")]
        public IPReportResponseCode ResponseCode { get; set; }

        /// <summary>
        /// Contains the message that corrosponds to the reponse code.
        /// </summary>
        [JsonProperty("verbose_msg")]
        public string VerboseMsg { get; set; }
    }
}
