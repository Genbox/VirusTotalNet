using System;
using System.Collections.Generic;
using RestSharp.Deserializers;

namespace VirusTotalNET.Objects
{
    public class FileReport
    {
        //
        //  Public API Items
        //

        /// <summary>
        /// MD5 hash of the resource.
        /// </summary>
        public string MD5 { get; set; }

        /// <summary>
        /// A permanent link that points to this specific scan.
        /// </summary>
        public string Permalink { get; set; }

        /// <summary>
        /// How many engines flagged this resource.
        /// </summary>
        public int Positives { get; set; }

        /// <summary>
        /// Contains the id of the resource. Can be a SHA256, MD5 or other hash type.
        /// </summary>
        public string Resource { get; set; }

        /// <summary>
        /// The response code. Use this to determine the status of the report.
        /// </summary>
        public ReportResponseCode ResponseCode { get; set; }

        /// <summary>
        /// The date the resource was last scanned.
        /// </summary>
        public DateTime ScanDate { get; set; }

        /// <summary>
        /// Contains the scan id for this result.
        /// </summary>
        public string ScanId { get; set; }

        /// <summary>
        /// The scan results from each engine.
        /// </summary>
        public Dictionary<string, ScanEngine> Scans { get; set; }

        /// <summary>
        /// SHA1 hash of the resource.
        /// </summary>
        public string SHA1 { get; set; }

        /// <summary>
        /// SHA256 hash of the resource.
        /// </summary>
        public string SHA256 { get; set; }

        /// <summary>
        /// How many engines scanned this resource.
        /// </summary>
        public int Total { get; set; }

        /// <summary>
        /// Contains the message that corresponds to the reponse code.
        /// </summary>
        public string VerboseMsg { get; set; }

        // Copyright Keith J. Jones © 2016

        //
        //  Private API Items
        //

        /// <summary>
        /// Valid for private API only
        /// </summary>
        [DeserializeAs(Name = "ITW_urls")]
        public List<string> ITWUrls { get; set; }

        /// <summary>
        /// Valid for private API only
        /// </summary>
        public FileReportAdditionalInfo AdditionalInfo { get; set; }

        public float CommunityReputation { get; set; }

        public DateTime FirstSeen { get; set; }

        public float HarmlessVotes { get; set; }

        public DateTime LastSeen { get; set; }

        public string MaliciousVotes { get; set; }

    }


}