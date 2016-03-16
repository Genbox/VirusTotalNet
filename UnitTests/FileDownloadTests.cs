// Copyright Keith J. Jones © 2016

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using VirusTotalNET;
using VirusTotalNET.Exceptions;
using VirusTotalNET.Objects;
using System.Configuration;
using System.IO;
using System.Security.Cryptography;


namespace UnitTests
{
    [TestClass]

    public class FileDownloadTests
    {
        private static VirusTotal _virusTotal;

        [ClassInitialize]
        public static void Initialize(TestContext context)
        {
            _virusTotal = new VirusTotal(ConfigurationManager.AppSettings["ApiKey"]);
            // This all requires a private key
            _virusTotal.IsPrivateKey = true;
        }

        [TestMethod]
        public void DownloadMalwareFile()
        {
            string hash = "44cda81782dc2a346abd7b2285530c5f";
            string dest = "44cda81782dc2a346abd7b2285530c5f.bin";

            File.Delete(dest);

            Assert.AreEqual(true, _virusTotal.GetFileDownload(hash, dest));

            Assert.AreEqual(true,File.Exists(dest));

            using (var md5 = MD5.Create())
            {
                using (var stream = File.OpenRead(dest))
                {
                    byte[] binarymd5 = md5.ComputeHash(stream);
                    string testmd5 = GetMD5Hash(binarymd5);
                    Assert.AreEqual(hash, testmd5);
                }

            }

            File.Delete(dest);
        }

        [TestMethod]
        public void DownloadUnknownMalwareFile()
        {
            string hash = "44cda81782dc2a346abd7b2285530c5a";
            string dest = "44cda81782dc2a346abd7b2285530c5a.bin";

            File.Delete(dest);

            Assert.AreEqual(false, _virusTotal.GetFileDownload(hash, dest));

            File.Delete(dest);
        }

        [TestMethod]
        [ExpectedException(typeof(System.IO.DirectoryNotFoundException),
            "Count not find a part of the path")]
        public void DownloadMalwareFileBadPath()
        {
            string hash = "44cda81782dc2a346abd7b2285530c5f";
            string dest = "C:\\DoesNotExist\\44cda81782dc2a346abd7b2285530c5f.bin";

            File.Delete(dest);

            Assert.AreEqual(true, _virusTotal.GetFileDownload(hash, dest));

            Assert.AreEqual(true, File.Exists(dest));

            using (var md5 = MD5.Create())
            {
                using (var stream = File.OpenRead(dest))
                {
                    byte[] binarymd5 = md5.ComputeHash(stream);
                    string testmd5 = GetMD5Hash(binarymd5);
                    Assert.AreEqual(hash, testmd5);
                }

            }

            File.Delete(dest);
        }


        // Creates hex string from bytes
        static string GetMD5Hash(byte[] hash)
        {
            StringBuilder myStringBuilder = new StringBuilder();

            for (int i = 0; i < hash.Length; i++)
            {
                myStringBuilder.Append(hash[i].ToString("x2"));
            }

            return myStringBuilder.ToString();
        }

    }
}
