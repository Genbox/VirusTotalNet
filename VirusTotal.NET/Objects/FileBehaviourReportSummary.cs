// Copyright Keith J. Jones © 2016

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VirusTotalNET.Objects
{
    public class FileBehaviourReportSummary
    {
        public List<string> Files { get; set; }
        public List<string> Keys { get; set; }
        public List<string> Mutexes { get; set; }
    }
}
