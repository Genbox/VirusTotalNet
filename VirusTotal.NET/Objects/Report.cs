using System;
using System.Collections.Generic;

namespace VirusTotalNET.Objects
{
    public class Report : IResponseCode
    {
        public string Resource { get; set; }
        public string ScanId { get; set; }
        public string Md5 { get; set; }
        public string Sha1 { get; set; }
        public string Sha256 { get; set; }
        public DateTime ScanDate { get; set; }
        public int Positives { get; set; }
        public int Total { get; set; }
        public string Permalink { get; set; }
        public List<ScanEngine> Scans { get; set; }
        public int ResponseCode { get; set; }
        public string VerboseMsg { get; set; }
    }
}