// Copyright Keith J. Jones © 2016

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VirusTotalNET.Objects
{
    /// <summary>
    /// A class to hold the file behaviour process information
    /// </summary>
    public class FileBehaviourReportProcess
    {
        public List<FileBehaviourReportProcessCall> Calls { get; set; }
        public string FirstSeen { get; set; }
        public string ParentId { get; set; }
        public string ProcessId { get; set; }
        public string ProcessName { get; set; }
    }
}
