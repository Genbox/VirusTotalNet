namespace VirusTotalNET.Objects
{
    public enum ReportResponseCode
    {
        /// <summary>
        /// The requested item is still queued for analysis.
        /// </summary>
        StillQueued = -2,
        
        /// <summary>
        /// There was an error in the request
        /// </summary>
        Error = -1,

        /// <summary>
        /// The item you searched for was not present in VirusTotal's dataset.
        /// </summary>
        NotPresent = 0,

        /// <summary>
        /// The item was indeed present and it could be retrieved.
        /// </summary>
        Present = 1
    }
}