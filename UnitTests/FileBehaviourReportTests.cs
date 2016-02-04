// Copyright Keith J. Jones © 2016

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using VirusTotalNET;
using VirusTotalNET.Exceptions;
using VirusTotalNET.Objects;
using System.Configuration;

namespace UnitTests
{
    [TestClass]
    public class FileBehaviourReportTests
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
        public void GetReportKnownBehaviour()
        {
            string hash = "44cda81782dc2a346abd7b2285530c5f";

            FileBehaviourReport myReport = _virusTotal.GetFileBehaviour(hash);

            //It should always be in the VirusTotal database.
            Assert.IsNotNull(myReport.Info);
        }

        [TestMethod]
        public void GetReportUnknownBehaviour()
        {
            string hash = "44cda81782dc2a346abd7b2285530c5e";

            FileBehaviourReport myReport = _virusTotal.GetFileBehaviour(hash);

            //It should not be in the VirusTotal database.
            Assert.IsNull(myReport.Info);
        }

    }
}
