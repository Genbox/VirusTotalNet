// Copyright Keith J. Jones © 2016

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VirusTotalNET.Objects
{
    /// <summary>
    /// A class to hold the URL distribution reports
    /// </summary>
    public class UrlDistributionReport
    {
        public int Positives { get; set; }
        public long Timestamp { get; set; }
        public int Total { get; set; }
        public string Url { get; set; }
    }
}
