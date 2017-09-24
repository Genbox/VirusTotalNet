namespace VirusTotalNET.ResponseCodes
{
    public enum FileReportResponseCode
    {
        /// <summary>
        /// The resource is still being scanned
        /// </summary>
        Queued = -2,

        /// <summary>
        /// The item you searched for was not present in VirusTotal's dataset.
        /// </summary>
        NotPresent = 0,

        /// <summary>
        /// The item was present and it could be retrieved.
        /// </summary>
        Present = 1
    }
}