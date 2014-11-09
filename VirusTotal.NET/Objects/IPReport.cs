using System.Collections.Generic;

namespace VirusTotalNET.Objects
{
    public class IPReport
    {
        public string AsOwner { get; set; }

        public int ASN { get; set; }

        public string Country { get; set; }

        public List<Resolution> Resolutions { get; set; }

        public List<DetectedUrl> DetectedUrls { get; set; }

        public List<Sample> DetectedCommunicatingSamples { get; set; }

        public List<Sample> DetectedDownloadedSamples { get; set; }

        public List<Sample> DetectedReferrerSamples { get; set; }

        public List<Sample> UndetectedCommunicatingSamples { get; set; }

        public List<Sample> UndetectedDownloadedSamples { get; set; }

        /// <summary>
        /// The response code. Use this to determine the status of the report.
        /// </summary>
        public IPReportResponseCode ResponseCode { get; set; }

        /// <summary>
        /// Contains the message that corrosponds to the reponse code.
        /// </summary>
        public string VerboseMsg { get; set; }
    }
}
