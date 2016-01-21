using System;
using RestSharp.Deserializers;

namespace VirusTotalNET.Objects
{
    public class Sample
    {
        [DeserializeAs(Name = "date")]
        public DateTime Date { get; set; }

        [DeserializeAs(Name = "positives")]
        public int Positives { get; set; }

        [DeserializeAs(Name = "total")]
        public int Total { get; set; }

        [DeserializeAs(Name = "sha256")]
        public string Sha256 { get; set; }
    }
}