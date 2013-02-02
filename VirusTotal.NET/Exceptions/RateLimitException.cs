using System;

namespace VirusTotalNET.Exceptions
{
    /// <summary>
    /// Exception that is thrown when the rate limit has been hit.
    /// </summary>
    public class RateLimitException : Exception
    {
        public RateLimitException(string message)
            : base(message)
        {
        }
    }
}
