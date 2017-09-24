using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using VirusTotalNET.Exceptions;

namespace VirusTotalNET.DateTimeParsers
{
    public class UnixTimeConverter : DateTimeConverterBase
    {
        private static DateTime _epoc = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        private static DateTime FromUnix(long unixTime)
        {
            return _epoc.AddSeconds(unixTime).ToLocalTime();
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            throw new NotImplementedException();
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            if (reader.Value == null)
                return 0;

            long value;
            try
            {
                value = (long)reader.Value;
            }
            catch (InvalidCastException)
            {
                throw new InvalidDateTimeException("Invalid date/time from VirusTotal. Tried to parse: " + reader.Value);
            }

            return FromUnix(value);
        }
    }
}