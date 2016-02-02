// Copyright Keith J. Jones © 2016

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using RestSharp.Deserializers;
using System.Net;

namespace VirusTotalNET.Objects
{
    public class UrlReportAdditionalInfo
    {
        // This may have a bug, can't figure out why it is not picking up
        [DeserializeAs(Name = "Dr.Web category")]
        public string DrWebCategory { get; set; }

        [DeserializeAs(Name = "Response code")]
        public int ResponseCode { get; set; }

        [DeserializeAs(Name = "Response content SHA-256")]
        public string ResponseContentSHA256 { get; set; }

        [DeserializeAs(Name = "Response headers")]
        public Dictionary<string, string> ResponseHeaders { get; set; }

        [DeserializeAs(Name = "URL after redirects")]
        public string URLAfterRedirects { get; set; }

        [DeserializeAs(Name = "Websense ThreatSeeker category")]
        public string WebsenseThreatSeekerCategory { get; set; }

        [DeserializeAs(Name = "Webutation domain info")]
        public Dictionary<string, string> WebutationDomainInfo { get; set; }

        [DeserializeAs(Name = "Wepawet report")]
        public string WepawetReport { get; set; }

        [DeserializeAs(Name = "filescan_permaid")]
        public string FileScanPermaId { get; set; }

        public string Resolution { get; set; }
    }
}
