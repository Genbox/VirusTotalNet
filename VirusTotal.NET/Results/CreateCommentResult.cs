using Newtonsoft.Json;
using VirusTotalNET.ResponseCodes;

namespace VirusTotalNET.Results
{
    public class CreateCommentResult
    {
        [JsonProperty("response_code")]
        public CommentResponseCode ResponseCode { get; set; }

        /// <summary>
        /// Contains the message that corresponds to the response code.
        /// </summary>
        [JsonProperty("verbose_msg")]
        public string VerboseMsg { get; set; }
    }
}