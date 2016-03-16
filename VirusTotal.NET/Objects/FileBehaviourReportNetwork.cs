// Copyright Keith J. Jones © 2016

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VirusTotalNET.Objects
{
    /// <summary>
    /// Class for holding file behaviour network info
    /// </summary>
    public class FileBehaviourReportNetwork
    {
        public List<FileBehaviourReportNetworkDns> Dns { get; set; }
        public List<string> Hosts { get; set; }
        public List<Dictionary<string, string>> Http { get; set; }
        public List<FileBehaviourReportNetworkConnection> Tcp { get; set; }
        public List<FileBehaviourReportNetworkConnection> Udp { get; set; }
    }
}
