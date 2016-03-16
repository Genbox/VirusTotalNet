// Copyright Keith J. Jones © 2016

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VirusTotalNET.Objects
{
    /// <summary>
    /// Class to hold the process tree item
    /// </summary>
    public class FileBehaviourReportProcessTreeItem
    {
        // Double check this implementation
        public List<string> Children { get; set; }
        public string Name { get; set; }
        public string Pid { get; set; }
    }
}
