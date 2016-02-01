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

        // Copyright Keith J. Jones © 2016
        [TestMethod]
        public void GetPublicReportForKnownFile()
        {
            //Create a hash of the EICAR test virus. See http://www.eicar.org/86-0-Intended-use.html
            string hash = HashHelper.GetMD5(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

            FileReport fileReport = _virusTotal.GetFileReport(hash);

            //It should always be in the VirusTotal database.
            Assert.AreEqual(ReportResponseCode.Present, fileReport.ResponseCode);
            Assert.IsNull(fileReport.AdditionalInfo);
        }

        // Copyright Keith J. Jones © 2016
        [TestMethod]
        public void GetPrivateReportForKnownFile()
        {
            _virusTotal.IsPrivateKey = true;

            //Create a hash of the EICAR test virus. See http://www.eicar.org/86-0-Intended-use.html
            string hash = HashHelper.GetMD5(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

            FileReport fileReport = _virusTotal.GetFileReport(hash);

            //It should always be in the VirusTotal database.
            Assert.AreEqual(ReportResponseCode.Present, fileReport.ResponseCode);
            Assert.IsNotNull(fileReport.AdditionalInfo);

            _virusTotal.IsPrivateKey = false;
        }

        // Copyright Keith J. Jones © 2016
        [TestMethod]
        public void GetPrivateReportForKnownFileWithBehaviour()
        {
            _virusTotal.IsPrivateKey = true;

            // This hash has known behaviour data
            string hash = "44cda81782dc2a346abd7b2285530c5f";

            FileReport fileReport = _virusTotal.GetFileReport(hash);

            //It should always be in the VirusTotal database.
            Assert.AreEqual(ReportResponseCode.Present, fileReport.ResponseCode);
            Assert.IsNotNull(fileReport.AdditionalInfo);

            _virusTotal.IsPrivateKey = false;
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

            FileReport fileReport = _virusTotal.GetFileReport(fileInfo);

            //It should not be in the VirusTotal database already, which means it should return error.
            Assert.AreEqual(ReportResponseCode.NotPresent, fileReport.ResponseCode);
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

            FileReport fileReport = _virusTotal.GetFileReport(result.ScanId);

            //It should not be in the VirusTotal database already, which means it should return error.
            Assert.AreEqual(ReportResponseCode.StillQueued, fileReport.ResponseCode);
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidResourceException))]
        public void GetReportForInvalidResource()
        {
            FileReport fileReport = _virusTotal.GetFileReport("aaaaaaaaaaa");
        }
    }
}