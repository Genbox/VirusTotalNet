using System;
using System.Globalization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using VirusTotalNET.Exceptions;

namespace VirusTotalNET.DateTimeParsers
{
    public class YearMonthDayConverter : DateTimeConverterBase
    {
        private readonly CultureInfo _culture = new CultureInfo("en-us");
        private const string _newDateTimeFormat = "yyyyMMdd";
        private const string _oldDateTimeFormat = "yyyyMMddHHmmss";

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            writer.DateFormatString = _newDateTimeFormat;
            writer.WriteValue(value);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            if (reader.Value == null)
                return DateTime.MinValue;

            if (!(reader.Value is string))
                throw new InvalidDateTimeException("Invalid date/time from VirusTotal. Tried to parse: " + reader.Value);

            string value = (string)reader.Value;

            //VT sometimes have really old data that return '-' in timestamps
            if (value.Equals("-", StringComparison.OrdinalIgnoreCase))
                return DateTime.MinValue;

            //New format
            if (DateTime.TryParseExact(value, _newDateTimeFormat, _culture, DateTimeStyles.AllowWhiteSpaces, out DateTime result))
                return result;

            //Old format
            if (DateTime.TryParseExact(value, _oldDateTimeFormat, _culture, DateTimeStyles.AllowWhiteSpaces, out result))
                return result;

            throw new InvalidDateTimeException("Invalid date/time from VirusTotal. Tried to parse: " + value);
        }
    }
}