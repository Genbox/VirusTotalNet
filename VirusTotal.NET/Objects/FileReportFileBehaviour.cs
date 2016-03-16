// Copyright Keith J. Jones © 2016

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VirusTotalNET.Objects
{
    /// <summary>
    /// Class to hold behaviour information
    /// </summary>
    public class FileReportFileBehaviour
    {
        public List<string> Extra { get; set; }

        public Dictionary<string, List<Dictionary<string, string>>> FileSystem { get; set; }

        public List<Dictionary<string,string>> Hooking { get; set; }

        public Dictionary<string, List<Dictionary<string,string>>> Mutex { get; set; }

        public Dictionary<string, List<string>> Network { get; set; }

        public Dictionary<string, List<Dictionary<string, string>>> Registry { get; set; }

        public List<Dictionary<string,string>> RuntimeDLLs { get; set; }

        public Dictionary<string, List<Dictionary<string, string>>> Service { get; set; }

        public Dictionary<string, List<Dictionary<string, string>>> Windows { get; set; }

    }
}
