using System.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using VirusTotalNET;

namespace UnitTests
{
    [TestClass]
    public class CreateCommentTests
    {
        private static VirusTotal _virusTotal;

        [ClassInitialize]
        public static void Initialize(TestContext context)
        {
            _virusTotal = new VirusTotal(ConfigurationManager.AppSettings["ApiKey"]);
        }

        [TestMethod]
        public void CreateValidComment()
        {
            //TODO
        }

        [TestMethod]
        public void CreateInvalidComment()
        {
            //TODO
        }
    }
}
