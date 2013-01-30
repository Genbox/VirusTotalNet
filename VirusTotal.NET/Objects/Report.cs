using System;
using System.Collections.Generic;

namespace VirusTotalNET.Objects
{
    public class Report : IResponseCode
    {
        /// <summary>
        /// Contains the id of the resource. Can be a SHA256, MD5 or other hash type.
        /// </summary>
        public string Resource { get; set; }

        /// <summary>
        /// Contains the scan id for this result.
        /// </summary>
        public string ScanId { get; set; }

        /// <summary>
        /// MD5 hash of the resource.
        /// </summary>
        public string Md5 { get; set; }

        /// <summary>
        /// SHA1 hash of the resource.
        /// </summary>
        public string Sha1 { get; set; }

        /// <summary>
        /// SHA256 hash of the resource.
        /// </summary>
        public string Sha256 { get; set; }

        /// <summary>
        /// The date the resource was last scanned.
        /// </summary>
        public DateTime ScanDate { get; set; }

        /// <summary>
        /// How many engines flagged this resource.
        /// </summary>
        public int Positives { get; set; }

        /// <summary>
        /// How many engines scanned this resource.
        /// </summary>
        public int Total { get; set; }

        /// <summary>
        /// A permanent link that points to this specific scan.
        /// </summary>
        public string Permalink { get; set; }

        /// <summary>
        /// The scan results from each engine.
        /// </summary>
        public List<ScanEngine> Scans { get; set; }

        /// <summary>
        /// 0  : The item you searched for was not present in VirusTotal's dataset.
        /// -2 : The requested item is still queued for analysis.
        /// 1  : The item was indeed present and it could be retrieved.
        /// </summary>
        public int ResponseCode { get; set; }

        /// <summary>
        /// Contains the message that corrosponds to the reponse code.
        /// </summary>
        public string VerboseMsg { get; set; }
    }
}