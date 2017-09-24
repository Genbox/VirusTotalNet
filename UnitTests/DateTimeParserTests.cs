using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using VirusTotalNET.Objects;
using VirusTotalNET.Results;
using VirusTotalNET.UnitTests.TestInternals;
using Xunit;

namespace VirusTotalNET.UnitTests
{
    public class DateTimeParserTests : TestBase
    {
        [Fact]
        public void YearMonthDayConverterTest()
        {
            FileReport fileReport = new FileReport
            {
                ScanDate = new DateTime(2017, 08, 10),
                Scans = new Dictionary<string, ScanEngine>()
            };

            ScanEngine scan1 = new ScanEngine { Detected = true, Result = "Malware.Undefined!8.C (cloud:nWdia2XyY0T)", Version = "25.0.0.1", Update = new DateTime(2017, 07, 26) };
            ScanEngine scan2 = new ScanEngine { Detected = false, Result = null, Version = "5.5.1.3", Update = new DateTime(2017, 07, 25) };
            ScanEngine scan3 = new ScanEngine { Detected = false, Result = null, Version = "1.0.1.223", Update = new DateTime(2017, 07, 18) };

            fileReport.Scans.Add("Rising", scan1);
            fileReport.Scans.Add("Yandex", scan2);
            fileReport.Scans.Add("SentinelOne", scan3);

            string fileReportJson = JsonConvert.SerializeObject(fileReport.Scans);
            Assert.Contains("\"Update\":\"20170726\"", fileReportJson);
            Assert.Contains("\"Update\":\"20170725\"", fileReportJson);
            Assert.Contains("\"Update\":\"20170718\"", fileReportJson);
        }
    }
}