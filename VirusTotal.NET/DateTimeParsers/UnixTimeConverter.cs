using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

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
            double value = (double)reader.Value;
            return FromUnix(value);
        }
    }
}