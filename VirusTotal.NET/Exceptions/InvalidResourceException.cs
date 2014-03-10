using System;

namespace VirusTotalNET.Exceptions
{
    public class InvalidResourceException : Exception
    {
        public InvalidResourceException(string message) : base(message) { }
    }
}