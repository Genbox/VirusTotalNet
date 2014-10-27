using System;

namespace VirusTotalNET
{
    public static class UnixTimeHelper
    {
        private static DateTime epoc = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        public static DateTime FromUnix(double unixTime)
        {
            return epoc.AddSeconds(unixTime).ToLocalTime();
        }

        public static double FromDateTime(DateTime dateTime)
        {
            return (dateTime - epoc.ToLocalTime()).TotalSeconds;
        }
    }
}
