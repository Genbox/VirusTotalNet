using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using VirusTotalNet.Helpers;

namespace VirusTotalNet.Internal.DateTimeParsers;

internal class UnixTimeConverter : DateTimeConverterBase
{
    private static DateTime _epoc = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

    private static DateTime FromUnix(long unixTime)
    {
        return _epoc.AddSeconds(unixTime).ToLocalTime();
    }

    public override void WriteJson(JsonWriter writer, object? value, JsonSerializer serializer)
    {
        throw new NotSupportedException();
    }

    public override object? ReadJson(JsonReader reader, Type objectType, object? existingValue, JsonSerializer serializer)
    {
        if (reader.Value == null)
            return null;

        string stringVal = reader.Value.ToString();

        if (string.IsNullOrWhiteSpace(stringVal))
            return DateTime.MinValue;

        if (!ResourcesHelper.IsNumeric(stringVal))
            return DateTime.MinValue;

        return FromUnix(long.Parse(stringVal));
    }
}