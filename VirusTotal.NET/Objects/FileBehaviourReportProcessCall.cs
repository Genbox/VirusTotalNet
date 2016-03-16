// Copyright Keith J. Jones © 2016

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VirusTotalNET.Objects
{
    /// <summary>
    /// A class to hold the process calls
    /// </summary>
    public class FileBehaviourReportProcessCall
    {
        public string Api { get; set; }
        public List<FileBehaviourReportProcessCallArgument> Arguments { get; set; }
        public string Category { get; set; }
        public float Repeated { get; set; }
        public string Return { get; set; }
        public string Status { get; set; }
        public string Timestamp { get; set; }
    }
}
