using System;
using Newtonsoft.Json;
using VirusTotalNet.Internal.DateTimeParsers;

namespace VirusTotalNet.Objects;

public class ScanEngine
{
    /// <summary>
    /// True if the engine flagged the resource.
    /// </summary>
    public bool Detected { get; set; }

    /// <summary>
    /// Version of the engine.
    /// </summary>
    public string Version { get; set; }

    /// <summary>
    /// Contains the name of the malware, if any.
    /// </summary>
    public string Result { get; set; }

    /// <summary>
    /// The date of the latest signatures of the engine.
    /// </summary>
    [JsonConverter(typeof(YearMonthDayConverter))]
    public DateTime Update { get; set; }
}