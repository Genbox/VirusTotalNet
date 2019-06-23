using System;

namespace VirusTotalNet.Objects
{
    public class SampleWithDate
    {
        public DateTime Date { get; set; }
        public int Positives { get; set; }
        public int Total { get; set; }
        public string Sha256 { get; set; }
    }
}