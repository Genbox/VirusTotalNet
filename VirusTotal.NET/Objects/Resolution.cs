using System;
using Newtonsoft.Json;

namespace VirusTotalNET.Objects
{
    public class Resolution
    {
        [JsonProperty("last_resolved")]
        public DateTime LastResolved { get; set; }

        public string Hostname { get; set; }

        [JsonProperty("ip_address")]
        public string IPAddress { get; set; }
    }
}
