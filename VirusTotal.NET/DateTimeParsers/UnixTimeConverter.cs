using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using VirusTotalNET.Exceptions;

namespace VirusTotalNET.DateTimeParsers
{
    public class UnixTimeConverter : DateTimeConverterBase
    {
        private static DateTime _epoc = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        private static DateTime FromUnix(double unixTime)
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

            double value;
            try
            {
                value = (double)reader.Value;
            }
            catch (InvalidCastException)
            {
                throw new InvalidDateTimeException("Invalid datetime from VirusTotal. Tried to parse: " + reader.Value);
            }

            return FromUnix(value);
        }
    }
}