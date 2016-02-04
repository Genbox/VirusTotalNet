// Copyright Keith J. Jones © 2016

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VirusTotalNET.Objects
{
    /// <summary>
    /// Class for holding behaviour info
    /// </summary>
    public class FileBehaviourReportInfo
    {
        public string Duration { get; set; }
        // These could be DateTimes, maybe
        public string Ended { get; set; }
        public string Started { get; set; }
        public string Version { get; set; }
    }
}
