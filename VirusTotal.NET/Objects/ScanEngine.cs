using System;
using System.Globalization;
using RestSharp.Deserializers;

namespace VirusTotalNET.Objects
{
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

		[DeserializeAs(Name = "update")]
		public string UpdateString
		{
			get { return UpdateDate.ToString(); }
			set
			{
				DateTime result;

				if (DateTime.TryParseExact(value, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out result))
					UpdateDate = result;
			}
		}

        /// <summary>
        /// The date of the latest signatures of the engine.
        /// </summary>
		public DateTime UpdateDate { get; set; }
	}
}