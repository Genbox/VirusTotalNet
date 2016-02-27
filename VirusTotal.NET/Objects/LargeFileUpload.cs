namespace VirusTotalNET.Objects
{
    /// <summary>
    /// For files bigger than 32MB, we need a special Url to upload them
    /// </summary>
    public class LargeFileUpload
    {
        /// <summary>
        /// The special upload url to be used
        /// </summary>
        public string UploadUrl { get; set; } 
    }
}