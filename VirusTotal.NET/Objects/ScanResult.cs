namespace VirusTotalNET.Objects
{
    public class ScanResult : IResponseCode
    {
        /// <summary>
        ///  1: The file corresponding to the given hash was successfully queued.
        /// -1: The file was not present in the store.
        ///  0: An error occured.
        /// </summary>
        public int ResponseCode { get; set; }
        public string VerboseMsg { get; set; }
        public string Resource { get; set; }
        public string ScanId { get; set; }
        public string Permalink { get; set; }
        public string Sha256 { get; set; }
    }
}