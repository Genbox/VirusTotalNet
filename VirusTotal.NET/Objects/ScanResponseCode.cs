namespace VirusTotalNET.Objects
{
    public enum ScanResponseCode
    {
        /// <summary>
        /// An error occured.
        /// </summary>
        Error = 0,

        /// <summary>
        /// The file corresponding to the given hash was successfully queued.
        /// </summary>
        Queued = 1
    }
}