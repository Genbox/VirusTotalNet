using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using VirusTotalNet.Internal.DateTimeParsers;
using VirusTotalNet.Objects;
using VirusTotalNet.ResponseCodes;

namespace VirusTotalNet.Results;

public class DomainReport
{
    [JsonProperty("Sophos category")]
    public string SophosCategory { get; set; }

    [JsonProperty("alphaMountain.ai category")]
    public string AlphaMountainCategory { get; set; }

    [JsonProperty("Comodo Valkyrie Verdict category")]
    public string ComodoValkyrieCategory { get; set; }

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
    public List<SampleWithDate> DetectedReferrerSamples { get; set; }

    [JsonProperty("detected_urls")]
    public List<DetectedUrl> DetectedUrls { get; set; }

    [JsonProperty("Dr.Web category")]
    public string DrWebCategory { get; set; }

    [JsonProperty("Forcepoint ThreatSeeker category")]
    public string ForcePointThreatSeekerCategory { get; set; }

    [JsonProperty("Opera domain info")]
    public string OperaDomainInfo { get; set; }

    public List<string> Pcaps { get; set; }

    public List<DomainResolution> Resolutions { get; set; }

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
    public List<SampleWithDate> UndetectedReferrerSamples { get; set; }

    [JsonProperty("undetected_urls")]
    public List<List<string>> UndetectedUrls { get; set; }

    [JsonProperty("Websense ThreatSeeker category")]
    public string WebsenseThreatSeekerCategory { get; set; }

    [JsonProperty("Webutation domain info")]
    public WebutationInfo WebutationDomainInfo { get; set; }

    [JsonProperty("whois")]
    public string WhoIs { get; set; }

    [JsonProperty("whois_timestamp", NullValueHandling = NullValueHandling.Ignore)]
    [JsonConverter(typeof(UnixTimeConverter))]
    public DateTime WhoIsTimestamp { get; set; }

    [JsonProperty("WOT domain info")]
    public WOTInfo WOTDomainInfo { get; set; }

    [JsonProperty("response_code")]
    public DomainResponseCode ResponseCode { get; set; }

    /// <summary>
    /// Contains the message that corresponds to the response code.
    /// </summary>
    [JsonProperty("verbose_msg")]
    public string VerboseMsg { get; set; }
}