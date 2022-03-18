using Newtonsoft.Json;

namespace VirusTotalNet.Internal.Objects;

internal class LargeFileUpload
{
    [JsonProperty("upload_url")]
    public string UploadUrl { get; set; }
}