// Copyright Keith J. Jones © 2016

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VirusTotalNET.Objects
{
    /// <summary>
    /// Class for hoding behaviour
    /// </summary>
    public class FileBehaviourReportBehaviour
    {
        public List<FileBehaviourReportProcess> Processes { get; set; }
        public List<FileBehaviourReportProcessTreeItem> ProcessTree { get; set; }
        public FileBehaviourReportSummary Summary { get; set; }
    }
}
