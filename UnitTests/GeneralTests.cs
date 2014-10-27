using Microsoft.VisualStudio.TestTools.UnitTesting;
using VirusTotalNET;
using VirusTotalNET.Exceptions;

namespace UnitTests
{
    [TestClass]
    public class GeneralTests
    {
        [TestMethod]
        [ExpectedException(typeof(AccessDeniedException))]
        public void UnauthorizedScan()
        {
            VirusTotal virusTotal = new VirusTotal("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"); //64 characters
            virusTotal.GetFileReport("ca6d91bad9d5d5698c92dc64295a15a6"); //conficker MD5 hash
        }

        [TestMethod]
        public void GetPublicUrl()
        {
            //TODO
        }
    }
}
