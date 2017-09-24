using System.Linq;
using VirusTotalNET.UnitTests.TestInternals;
using Xunit;

namespace VirusTotalNET.UnitTests
{
    public class TestDataTests
    {
        [Fact]
        public void TestUnknownIPv4()
        {
            string[] unknownIPv4S = TestData.GetUnknownIPv4s(3).ToArray();

            Assert.Equal("0.0.0.0", unknownIPv4S[0]);
            Assert.Equal("0.0.0.1", unknownIPv4S[1]);
            Assert.Equal("0.0.0.2", unknownIPv4S[2]);
        }
    }
}
