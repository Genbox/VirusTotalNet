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
    public class URLDistributionReportTests
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
        public void GetSummaryDefaultUrlDistribution()
        {
            List<UrlDistributionReport> myReports = _virusTotal.GetSummaryUrlDistribution();

            Assert.AreEqual(true, myReports.Count > 0);
        }

        [TestMethod]
        public void GetSummaryOneURLDistribution()
        {
            List<UrlDistributionReport> myReports = _virusTotal.GetSummaryUrlDistribution(1);

            Assert.AreEqual(1, myReports.Count);
        }

        [TestMethod]
        public void GetDetailedDefaultUrlDistribution()
        {
            List<UrlReport> myReports = _virusTotal.GetDetailedUrlDistribution();

            Assert.AreEqual(true, myReports.Count > 0);
        }

        [TestMethod]
        public void GetDetailedOneURLDistribution()
        {
            List<UrlReport> myReports = _virusTotal.GetDetailedUrlDistribution(1);

            Assert.AreEqual(1, myReports.Count);
        }


    }
}
