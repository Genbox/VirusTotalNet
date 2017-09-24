using System;

namespace VirusTotalNET.Exceptions
{
    /// <summary>
    /// Exception that is thrown when the file size exceeds the allowed.
    /// </summary>
    public class SizeLimitException : Exception
    {
        public SizeLimitException(long vtLimitBytes, long actualBytes)
            : base($"The file size limit on VirusTotal is {vtLimitBytes / 1024} KB. Your file is {actualBytes / 1024} KB")
        {
        }

        public SizeLimitException(long vtLimitBytes)
            : base($"The file size limit on VirusTotal is {vtLimitBytes / 1024} KB.")
        {
        }
    }
}
