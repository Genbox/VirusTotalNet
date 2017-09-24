namespace VirusTotalNET.Objects
{
    public class UrlScanEngine
    {
        /// <summary>
        /// True if the engine flagged the resource.
        /// </summary>
		public bool Detected { get; set; }

        /// <summary>
        /// Details about the detection
        /// </summary>
		public string Detail { get; set; }

        /// <summary>
        /// Contains the name of the malware, if any.
        /// </summary>
		public string Result { get; set; }
    }
}