using System;
using System.Configuration;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using VirusTotalNET;
using VirusTotalNET.Exceptions;
using VirusTotalNET.Objects;

namespace UnitTests
{
    [TestClass]
    public class FileReportTests
    {
        private static VirusTotal _virusTotal;

        [ClassInitialize]
        public static void Initialize(TestContext context)
        {
            _virusTotal = new VirusTotal(ConfigurationManager.AppSettings["ApiKey"]);
        }

        [TestMethod]
        public void GetReportForKnownFile()
        {
            //Create a hash of the EICAR test virus. See http://www.eicar.org/86-0-Intended-use.html
            string hash = HashHelper.GetMD5(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

            Report report = _virusTotal.GetFileReport(hash);

            //It should always be in the VirusTotal database.
            Assert.AreEqual(ReportResponseCode.Present, report.ResponseCode);
        }

        [TestMethod]
        public void GetMultipleReportForKnownFile()
        {
            //TODO
        }

        [TestMethod]
        public void GetReportForUnknownFile()
        {
            string guid = "VirusTotal.NET" + Guid.NewGuid();

            FileInfo fileInfo = new FileInfo("VirusTotal.NET-Test.txt");
            File.WriteAllText(fileInfo.FullName, guid);

            Report report = _virusTotal.GetFileReport(fileInfo);

            //It should not be in the VirusTotal database already, which means it should return error.
            Assert.AreEqual(ReportResponseCode.NotPresent, report.ResponseCode);
        }

        [TestMethod]
        public void GetMultipleReportForUnknownFile()
        {
            //TODO
        }

        [TestMethod]
        public void GetReportForRecentFile()
        {
            //We create an unknown file
            string guid = "VirusTotal.NET" + Guid.NewGuid();

            FileInfo fileInfo = new FileInfo("VirusTotal.NET-Test.txt");
            File.WriteAllText(fileInfo.FullName, guid);

            //Attempt to submit it for scan
            ScanResult result = _virusTotal.ScanFile(fileInfo);

            Report report = _virusTotal.GetFileReport(result.ScanId);

            //It should not be in the VirusTotal database already, which means it should return error.
            Assert.AreEqual(ReportResponseCode.StillQueued, report.ResponseCode);
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidResourceException))]
        public void GetReportForInvalidResource()
        {
            Report report = _virusTotal.GetFileReport("aaaaaaaaaaa");
        }
    }
}