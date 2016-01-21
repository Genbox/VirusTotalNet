using System;
using System.Collections.Generic;
using RestSharp.Deserializers;

namespace VirusTotalNET.Objects
{
    public class DomainReport
    {
        [DeserializeAs(Name = "Alexa category")]
        public string AlexaCategory { get; set; }

        [DeserializeAs(Name = "Alexa domain info")]
        public string AlexaDomainInfo { get; set; }

        [DeserializeAs(Name = "Alexa rank")]
        public int AlexaRank { get; set; }

        [DeserializeAs(Name = "BitDefender category")]
        public string BitDefenderCategory { get; set; }

        [DeserializeAs(Name = "BitDefender domain info")]
        public string BitDefenderDomainInfo { get; set; }

        [DeserializeAs(Name = "categories")]
        public List<string> Categories { get; set; }

        [DeserializeAs(Name = "detected_communicating_samples")]
        public List<Sample> DetectedCommunicatingSamples { get; set; }

        [DeserializeAs(Name = "detected_downloaded_samples")]
        public List<Sample> DetectedDownloadedSamples { get; set; }

        [DeserializeAs(Name = "detected_referrer_samples")]
        public List<Sample> DetectedReferrerSamples { get; set; }

        [DeserializeAs(Name = "detected_urls")]
        public List<DetectedUrl> DetectedUrls { get; set; }

        [DeserializeAs(Name = "Dr.Web category")]
        public string DrWebCategory { get; set; }

        [DeserializeAs(Name = "Opera domain info")]
        public string OperaDomainInfo { get; set; }

        [DeserializeAs(Name = "pcaps")]
        public List<string> Pcaps { get; set; }

        [DeserializeAs(Name = "resolutions")]
        public List<Resolution> Resolutions { get; set; }

        [DeserializeAs(Name = "response_code")]
        /// <summary>
        /// The response code. Use this to determine the status of the report.
        /// </summary>
        public ReportResponseCode ResponseCode { get; set; }

        [DeserializeAs(Name = "domain_siblings")]
        public List<string> Subdomains { get; set; }

        [DeserializeAs(Name = "TrendMicro category")]
        public string TrendMicroCategory { get; set; }

        [DeserializeAs(Name = "undetected_communicating_samples")]
        public List<Sample> UndetectedCommunicatingSamples { get; set; }

        [DeserializeAs(Name = "undetected_downloaded_samples")]
        public List<Sample> UndetectedDownloadedSamples { get; set; }

        [DeserializeAs(Name = "undetected_referrer_samples")]
        public List<Sample> UndetectedReferrerSamples { get; set; }

        [DeserializeAs(Name = "verbose_msg")]
        /// <summary>
        /// Contains the message that corrosponds to the reponse code.
        /// </summary>
        public string VerboseMsg { get; set; }

        [DeserializeAs(Name = "Websense ThreatSeeker category")]
        public string WebsenseThreatSeekerCategory { get; set; }

        [DeserializeAs(Name = "Webutation domain info")]
        public WebutationInfo WebutationDomainInfo { get; set; }

        [DeserializeAs(Name = "whois")]
        public string WhoIs { get; set; }

        [DeserializeAs(Name = "whois_timestamp")]
        public string WhoIsTimestamp { get; set; }

        public DateTime? WhoIsDateTime
        {
            get {
                if (WhoIsTimestamp != null)
                {
                    return UnixTimeHelper.FromUnix(double.Parse(WhoIsTimestamp));
                }
                else
                {
                    return null;
                }
            }
        }

        [DeserializeAs(Name = "WOT domain info")]
        public WotInfo WOTDomainInfo { get; set; }
    }
}
