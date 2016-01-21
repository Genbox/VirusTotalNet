using System;
using RestSharp.Deserializers;


namespace VirusTotalNET.Objects
{
    public class Resolution
    {
        [DeserializeAs(Name = "last_resolved")]
        public DateTime LastResolved { get; set; }

        public string Hostname { get; set; }

        [DeserializeAs(Name = "ip_address")]
        public string IPAddress { get; set; }
    }
}
