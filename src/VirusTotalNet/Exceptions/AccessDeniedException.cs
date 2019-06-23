using System;

namespace VirusTotalNet.Exceptions
{
    /// <summary>
    /// Exception that is thrown when you don't have access to the service.
    /// </summary>
    public class AccessDeniedException : Exception
    {
        public AccessDeniedException(string message)
            : base(message) { }
    }
}