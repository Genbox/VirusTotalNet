namespace VirusTotalNET.Objects
{
    public class ScanResult
    {
        /// <summary>
        /// The scan response code. Use this to determine the status of the scan.
        /// </summary>
        public ScanResponseCode ResponseCode { get; set; }

        /// <summary>
        /// Contains a verbose message that corrosponds to the reponse code.
        /// </summary>
        public string VerboseMsg { get; set; }

        /// <summary>
        /// Id of the resource.
        /// </summary>
        public string Resource { get; set; }

        /// <summary>
        /// The unique scan id of the resource.
        /// </summary>
        public string ScanId { get; set; }

        /// <summary>
        /// A unique link to this particular scan result.
        /// </summary>
        public string Permalink { get; set; }

        /// <summary>
        /// SHA256 hash of the resource.
        /// </summary>
        public string Sha256 { get; set; }
    }
}