using Newtonsoft.Json;

namespace VirusTotalNet.Objects;

public class WOTInfo
{
    [JsonProperty("Child safety")]
    public string ChildSafety { get; set; }

    public string Privacy { get; set; }

    public string Trustworthiness { get; set; }

    [JsonProperty("Vendor reliability")]
    public string VendorReliability { get; set; }
}