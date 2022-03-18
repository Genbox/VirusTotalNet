namespace VirusTotalNet.ResponseCodes;

public enum ScanFileResponseCode
{
    //Note: I don't think Error can happen.

    /// <summary>
    /// An error happened in the request.
    /// </summary>
    Error = 0,

    /// <summary>
    /// The requested item is still queued for analysis.
    /// </summary>
    Queued = 1
}