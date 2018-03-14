using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using VirusTotalNET.Helpers;

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
            string stringVal = reader.Value.ToString();

            if (string.IsNullOrWhiteSpace(stringVal))
                return DateTime.MinValue;

            if (!ResourcesHelper.IsNumeric(stringVal))
                return DateTime.MinValue;

            return FromUnix(long.Parse(stringVal));
        }
    }
}