using System;
using System.Collections.Generic;
using VirusTotalNET.Objects;
using VirusTotalNET.ResponseCodes;
using VirusTotalNET.Results;
using VirusTotalNET.UnitTests.TestInternals;
using Xunit;
using Json = Newtonsoft.Json.JsonConvert;

namespace VirusTotalNET.UnitTests
{
    public class DateTimeParserTests : TestBase
    {
        [Fact]
        public void YearMonthDayConverterTest()
        {
            var fileReport = new FileReport
            {
                ScanId = "c7058a1e490c3e9e0ec30958de95cc815e48dba004e54ceeb242085213a64afd-1501098588",
                SHA1 = "0466abcbb6be6301383ceff0d7ce996ff4e89517",
                Resource = "0466ABCBB6BE6301383CEFF0D7CE996FF4E89517",
                ResponseCode = ReportResponseCode.Present,
                ScanDate = new DateTime(2017, 08, 10),
                Permalink =
                    "https://www.virustotal.com/file/c7058a1e490c3e9e0ec30958de95cc815e48dba004e54ceeb242085213a64afd/analysis/1501098588/",
                VerboseMsg = "Scan finished, information embedded",
                Total = 3,
                Positives = 1,
                SHA256 = "c7058a1e490c3e9e0ec30958de95cc815e48dba004e54ceeb242085213a64afd",
                MD5 = "7e89844169e755775f09aa4724680281",
                Scans = new Dictionary<string, ScanEngine>()
            };

            var scan1 = new ScanEngine{Detected = true, Result = "Malware.Undefined!8.C (cloud:nWdia2XyY0T)", Version = "25.0.0.1", Update = new DateTime(2017,07,26)};
            var scan2 = new ScanEngine{Detected = false, Result = null, Version = "5.5.1.3", Update = new DateTime(2017, 07, 25) };
            var scan3 = new ScanEngine{Detected = false, Result = null, Version = "1.0.1.223", Update = new DateTime(2017, 07, 18) };

            fileReport.Scans.Add("Rising", scan1);
            fileReport.Scans.Add("Yandex", scan2);
            fileReport.Scans.Add("SentinelOne", scan3);

            var fileReportJson = Json.SerializeObject(fileReport.Scans);
            Assert.True(fileReportJson.Contains("\"Update\":\"20170726\""));
            Assert.True(fileReportJson.Contains("\"Update\":\"20170725\""));
            Assert.True(fileReportJson.Contains("\"Update\":\"20170718\""));
        }
    }
}
