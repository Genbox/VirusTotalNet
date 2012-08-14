using System;

namespace VirusTotalNET
{
    public class RateLimitException : Exception
    {
        public RateLimitException(string message)
            : base(message)
        {
        }
    }
}
