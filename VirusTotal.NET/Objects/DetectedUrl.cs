using System;
using RestSharp.Deserializers;

namespace VirusTotalNET.Objects
{
    public class DetectedUrl
    {
        [DeserializeAs(Name = "url")]
        public string Url { get; set; }

        [DeserializeAs(Name = "positives")]
        public int Positives { get; set; }

        [DeserializeAs(Name = "total")]
        public int Total { get; set; }

        [DeserializeAs(Name = "scan_date")]
        public DateTime ScanDate { get; set; }
    }
}
