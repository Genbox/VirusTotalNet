using System;

namespace VirusTotalNET
{
    public static class UnixTimeHelper
    {
        private static DateTime _epoc = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        public static DateTime FromUnix(double unixTime)
        {
            return _epoc.AddSeconds(unixTime).ToLocalTime();
        }

        public static double FromDateTime(DateTime dateTime)
        {
            return (dateTime - _epoc.ToLocalTime()).TotalSeconds;
        }
    }
}
