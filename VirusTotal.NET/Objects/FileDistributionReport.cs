// Copyright Keith J. Jones © 2016

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VirusTotalNET.Objects
{
    /// <summary>
    /// Class to hold file distribution information
    /// </summary>
    public class FileDistributionReport
    {
        public DateTime? FirstSeen { get; set; }
        public DateTime? LastSeen { get; set; }
        public string Link { get; set; }
        public string Md5 { get; set; }
        public string Name { get; set; }
        public float Positives { get; set; }
        public string PositivesDelta { get; set; }
        public string Sha1 { get; set; }
        public string Sha256 { get; set; }
        public int Size { get; set; }
        public string SourceCountry { get; set; }
        public string SourceId { get; set; }
        public string SSDeep { get; set; }
        public List<string> Tags { get; set; }
        public long Timestamp { get; set; }
        public int Total { get; set; }
        public string Type { get; set; }
        public string VHash { get; set; }

        public Dictionary<string,List<string>> Report { get; set; }
    }
}
