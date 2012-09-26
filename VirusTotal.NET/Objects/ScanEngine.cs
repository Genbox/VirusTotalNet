using System;
using System.Globalization;
using RestSharp.Deserializers;

namespace VirusTotalNET.Objects
{
	public class ScanEngine
	{
		public string Name { get; set; }
		public bool Detected { get; set; }
		public string Version { get; set; }
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

		public DateTime UpdateDate { get; set; }
	}
}