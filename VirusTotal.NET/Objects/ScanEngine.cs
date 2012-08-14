using System;
using RestSharp.Deserializers;

namespace VirusTotalNET.Objects
{
    public class ScanEngine
    {
        public string Name { get; set; }
        public bool Detected { get; set; }
        public string Version { get; set; }
        public string Result { get; set; }

        [AsDateTimeFormat("yyyyMMdd")]
        public DateTime Update { get; set; }
    }
}