using System;

namespace VirusTotalNet.Exceptions;

public class InvalidDateTimeException : Exception
{
    public InvalidDateTimeException(string message) : base(message) { }
}