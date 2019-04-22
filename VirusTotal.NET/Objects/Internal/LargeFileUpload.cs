using Newtonsoft.Json;

namespace VirusTotalNET.Objects.Internal
{
    internal class LargeFileUpload
    {
        [JsonProperty("upload_url")]
        public string UploadUrl { get; set; }
    }
}