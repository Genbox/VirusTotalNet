// Copyright Keith J. Jones © 2016

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using VirusTotalNET;
using VirusTotalNET.Exceptions;
using VirusTotalNET.Objects;
using System.Configuration;
using System.Collections.Generic;

namespace UnitTests
{
    [TestClass]
    public class FileDistributionReportTests
    {
        private static VirusTotal _virusTotal;

        [ClassInitialize]
        public static void Initialize(TestContext context)
        {
            _virusTotal = new VirusTotal(ConfigurationManager.AppSettings["ApiKey"]);
            // This all requires a private key
            _virusTotal.IsPrivateKey = true;
            _virusTotal.IsUnlimitedPrivateKey = true;
        }

        [TestMethod]
        public void GetDefaultFileDistribution()
        {
            List<FileDistributionReport> myReports = _virusTotal.GetFileDistribution();

            Assert.AreEqual(true, myReports.Count > 0);
        }

        [TestMethod]
        public void GetOneFileDistribution()
        {
            List<FileDistributionReport> myReports = _virusTotal.GetFileDistribution(true,1);

            Assert.AreEqual(1, myReports.Count);
        }

    }
}
