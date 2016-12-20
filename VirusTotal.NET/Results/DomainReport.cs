using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using VirusTotalNET.DateTimeParsers;
using VirusTotalNET.Objects;
using VirusTotalNET.ResponseCodes;

namespace VirusTotalNET.Results
{
    public class DomainReport
    {
        [JsonProperty("Alexa category")]
        public string AlexaCategory { get; set; }

        [JsonProperty("Alexa domain info")]
        public string AlexaDomainInfo { get; set; }

        [JsonProperty("Alexa rank")]
        public int AlexaRank { get; set; }

        [JsonProperty("BitDefender category")]
        public string BitDefenderCategory { get; set; }

        [JsonProperty("BitDefender domain info")]
        public string BitDefenderDomainInfo { get; set; }

        public List<string> Categories { get; set; }

        [JsonProperty("detected_communicating_samples")]
        public List<SampleWithDate> DetectedCommunicatingSamples { get; set; }

        [JsonProperty("detected_downloaded_samples")]
        public List<SampleWithDate> DetectedDownloadedSamples { get; set; }

        [JsonProperty("detected_referrer_samples")]
        public List<Sample> DetectedReferrerSamples { get; set; }

        [JsonProperty("detected_urls")]
        public List<DetectedUrl> DetectedUrls { get; set; }

        [JsonProperty("Dr.Web category")]
        public string DrWebCategory { get; set; }

        [JsonProperty("Opera domain info")]
        public string OperaDomainInfo { get; set; }

        public List<string> Pcaps { get; set; }

        public List<Resolution> Resolutions { get; set; }

        /// <summary>
        /// The response code. Use this to determine the status of the report.
        /// </summary>
        [JsonProperty("response_code")]
        public ReportResponseCode ResponseCode { get; set; }

        [JsonProperty("domain_siblings")]
        public List<string> DomainSiblings { get; set; }

        [JsonProperty("subdomains")]
        public List<string> SubDomains { get; set; }

        [JsonProperty("TrendMicro category")]
        public string TrendMicroCategory { get; set; }

        [JsonProperty("undetected_communicating_samples")]
        public List<SampleWithDate> UndetectedCommunicatingSamples { get; set; }

        [JsonProperty("undetected_downloaded_samples")]
        public List<SampleWithDate> UndetectedDownloadedSamples { get; set; }

        [JsonProperty("undetected_referrer_samples")]
        public List<Sample> UndetectedReferrerSamples { get; set; }

        /// <summary>
        /// Contains the message that corrosponds to the reponse code.
        /// </summary>
        [JsonProperty("verbose_msg")]
        public string VerboseMsg { get; set; }

        [JsonProperty("Websense ThreatSeeker category")]
        public string WebsenseThreatSeekerCategory { get; set; }

        [JsonProperty("Webutation domain info")]
        public WebutationInfo WebutationDomainInfo { get; set; }

        [JsonProperty("whois")]
        public string WhoIs { get; set; }

        [JsonProperty("whois_timestamp")]
        [JsonConverter(typeof(UnixTimeConverter))]
        public DateTime WhoIsTimestamp { get; set; }

        [JsonProperty("WOT domain info")]
        public WOTInfo WOTDomainInfo { get; set; }
    }
}