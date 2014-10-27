using RestSharp.Deserializers;

namespace VirusTotalNET.Objects
{
    public class WotInfo
    {
        [DeserializeAs(Name = "Child safety")]
        public string ChildSafety { get; set; }

        public string Privacy { get; set; }

        public string Trustworthiness { get; set; }

        [DeserializeAs(Name = "Vendor reliability")]
        public string VendorReliability { get; set; }

    }
}