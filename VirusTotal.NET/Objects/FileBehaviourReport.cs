// Copyright Keith J. Jones © 2016

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VirusTotalNET.Objects
{
    /// <summary>
    /// A class for a file behaviour report
    /// </summary>
    public class FileBehaviourReport
    {
        // Ugh - the API changes the spelling of behaviour 
        // from the API documentation!
        public FileBehaviourReportBehaviour Behavior { get; set; }
        public FileBehaviourReportInfo Info { get; set; }
        public FileBehaviourReportNetwork Network { get; set; }
       
    }
}
