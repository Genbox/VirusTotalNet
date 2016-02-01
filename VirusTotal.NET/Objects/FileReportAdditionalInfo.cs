// Copyright Keith J. Jones © 2016

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using RestSharp.Deserializers;

namespace VirusTotalNET.Objects
{
    /// <summary>
    /// Class for private API file reports
    /// </summary>
    public class FileReportAdditionalInfo
    {
        public List<FileReportsAutoStart> Autostart { get; set; }

        public List<string> CompressedParents { get; set; }

        public List<FileReportDetailedEmailParents> DetailedEmailParents { get; set; }

        public List<string> EmailParents { get; set; }

        public FileReportsExifTool ExifTool { get; set; }

        public string FirstSeenITW { get; set; }

        public string Magic { get; set; }

        public List<string> OverlayParents { get; set; }

        [DeserializeAs(Name = "pcap_parents")]
        public List<string> PCapParents { get; set; }

        public List<string> PEResourceParents { get; set; }

        public float PositivesDelta { get; set; }

        public string TRId { get; set; }

        public FileReportSigCheck SigCheck { get; set; }

        [DeserializeAs(Name = "behaviour-v1")]
        public FileReportFileBehaviour Behaviourv1 { get; set; }

        [DeserializeAs(Name = "clam-av-pua")]
        public string ClamAVPUA { get; set; }
    }
}
