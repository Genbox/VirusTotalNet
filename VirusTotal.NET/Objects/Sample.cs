using System;

namespace VirusTotalNET.Objects
{
    public class Sample
    {
        public int Positives { get; set; }
        public int Total { get; set; }
        public string Sha256 { get; set; }
        public DateTime Date { get; set; }
    }
}