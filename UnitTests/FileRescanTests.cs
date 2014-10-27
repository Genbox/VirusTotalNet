using System;
using System.Configuration;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using VirusTotalNET;
using VirusTotalNET.Objects;

namespace UnitTests
{
    [TestClass]
    public class FileRescanTests
    {
        private static VirusTotal _virusTotal;

        [ClassInitialize]
        public static void Initialize(TestContext context)
        {
            _virusTotal = new VirusTotal(ConfigurationManager.AppSettings["ApiKey"]);
        }

        [TestMethod]
        public void RescanKnownFile()
        {
            //Create the EICAR test virus. See http://www.eicar.org/86-0-Intended-use.html
            FileInfo fileInfo = new FileInfo("EICAR.txt");
            File.WriteAllText(fileInfo.FullName, @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

            ScanResult fileResult = _virusTotal.RescanFile(fileInfo);

            //It should always be in the VirusTotal database. We expect it to rescan it
            Assert.AreEqual(ScanResponseCode.Queued, fileResult.ResponseCode);
        }

        [TestMethod]
        public void RescanMultipleKnownFile()
        {
            //TODO
        }

        [TestMethod]
        public void RescanUnknownFile()
        {
            string guid = "VirusTotal.NET" + Guid.NewGuid();

            FileInfo fileInfo = new FileInfo("VirusTotal.NET-Test.txt");
            File.WriteAllText(fileInfo.FullName, guid);

            ScanResult fileResult = _virusTotal.RescanFile(fileInfo);

            //It should not be in the VirusTotal database already, which means it should return error.
            Assert.AreEqual(ScanResponseCode.Error, fileResult.ResponseCode);
        }

        [TestMethod]
        public void RescanMultipleUnknownFile()
        {
            //TODO
        }

        [TestMethod]
        public void RescanSmallFile()
        {
            ScanResult fileResult = _virusTotal.ScanFile(new byte[1], "VirusTotal.NET-Test.txt");

            //It has been scanned before, we expect it to return queued.
            Assert.AreEqual(ScanResponseCode.Queued, fileResult.ResponseCode);
        }

        [TestMethod]
        public void RescanLargeFile()
        {
            //Since rescan works on hashes, we expect the hash of this empty file (which is larger than the limit) is not present in the database.
            byte[] bytes = new byte[99 * 1023 * 1024]; //the weird size is because VT has some weird empty files in its database.
            string hash = HashHelper.GetMD5(bytes);
            ScanResult result = _virusTotal.RescanFile(hash);
            Assert.AreEqual(ScanResponseCode.Error, result.ResponseCode);
        }
    }
}
