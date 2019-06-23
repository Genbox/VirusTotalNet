using System.Collections.Generic;
using Newtonsoft.Json;
using VirusTotalNet.Objects;

namespace VirusTotalNet.Results
{
    public class CommentResult
    {
        /// <summary>
        /// A list of comments on the resource
        /// </summary>
        public List<UserComment> Comments { get; set; }

        /// <summary>
        /// Contains the message that corresponds to the response code.
        /// </summary>
        [JsonProperty("verbose_msg")]
        public string VerboseMsg { get; set; }
    }
}