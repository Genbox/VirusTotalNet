namespace VirusTotalNet.ResponseCodes;

public enum UrlReportResponseCode
{
    /// <summary>
    /// The item you searched for was not present in VirusTotal's dataset.
    /// </summary>
    NotPresent = 0,

    /// <summary>
    /// The item was indeed present and it could be retrieved.
    /// </summary>
    Present = 1
}