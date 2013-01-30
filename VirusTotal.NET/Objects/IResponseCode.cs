namespace VirusTotalNET.Objects
{
    public interface IResponseCode
    {
        /// <summary>
        /// The reponse code.
        /// </summary>
        int ResponseCode { get; set; }

        /// <summary>
        /// The message that corrosponds to the reponse code.
        /// </summary>
        string VerboseMsg { get; set; }
    }
}