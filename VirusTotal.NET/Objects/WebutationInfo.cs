using RestSharp.Deserializers;

namespace VirusTotalNET.Objects
{
    public class WebutationInfo
    {
        [DeserializeAs(Name = "Adult content")]
        public string AdultContent { get; set; }

        [DeserializeAs(Name = "Safety score")]
        public int SafetyScore { get; set; }

        public string Verdict { get; set; }
    }
}