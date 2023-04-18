using System;
using System.Globalization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using VirusTotalNet.Exceptions;
using VirusTotalNet.Helpers;

namespace VirusTotalNet.Internal.DateTimeParsers;

internal class YearMonthDayConverter : DateTimeConverterBase
{
    private readonly CultureInfo _culture = new CultureInfo("en-us");
    private const string _newDateTimeFormat = "yyyyMMdd";
    private const string _oldDateTimeFormat = "yyyyMMddHHmmss";

    public override void WriteJson(JsonWriter writer, object? value, JsonSerializer serializer)
    {
        writer.DateFormatString = _newDateTimeFormat;
        writer.WriteValue(value);
    }

    public override object ReadJson(JsonReader reader, Type objectType, object? existingValue, JsonSerializer serializer)
    {
        if (reader.Value is not string valueStr)
            return DateTime.MinValue;

        if (!ResourcesHelper.IsNumeric(valueStr))
            return DateTime.MinValue;

        //New format
        if (DateTime.TryParseExact(valueStr, _newDateTimeFormat, _culture, DateTimeStyles.AllowWhiteSpaces, out DateTime result))
            return result;

        //Old format
        if (DateTime.TryParseExact(valueStr, _oldDateTimeFormat, _culture, DateTimeStyles.AllowWhiteSpaces, out result))
            return result;

        throw new InvalidDateTimeException("Invalid date/time from VirusTotal. Tried to parse: " + valueStr);
    }
}