// Copyright Keith J. Jones © 2016

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VirusTotalNET.Objects
{
    /// <summary>
    /// Class to hold TCP information
    /// </summary>
    public class FileBehaviourReportNetworkConnection
    {
        public string Dport { get; set; }
        public string Dst { get; set; }
        public string Sport { get; set; }
        public string Src { get; set; }
    }
}
