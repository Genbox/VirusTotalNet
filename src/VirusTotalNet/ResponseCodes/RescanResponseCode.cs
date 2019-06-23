namespace VirusTotalNet.ResponseCodes
{
    public enum RescanResponseCode
    {
        /// <summary>
        /// There was an error in the request
        /// </summary>
        ResourceNotFound = 0,

        /// <summary>
        /// The requested item is still queued for analysis.
        /// </summary>
        Queued = 1
    }
}