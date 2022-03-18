using System.Linq;
using VirusTotalNet.Tests.TestInternals;
using Xunit;

namespace VirusTotalNet.Tests;

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