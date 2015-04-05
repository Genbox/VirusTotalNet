using System;

namespace VirusTotalNET.Exceptions
{
    /// <summary>
    /// Exception that is thrown when the number of resources exceed the allowed.
    /// </summary>
    public class ResourceLimitException : Exception
    {
        public ResourceLimitException(string message)
            : base(message)
        {
        }
    }
}
