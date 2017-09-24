using VirusTotalNET.Exceptions;
using VirusTotalNET.Helpers;
using VirusTotalNET.UnitTests.TestInternals;
using Xunit;

namespace VirusTotalNET.UnitTests
{
    public class ResourceHelperTests : TestBase
    {
        [Fact]
        public void ValidResources()
        {
            string[] values =
            {
                "99017f6eebbac24f351415dd410d522d",
                "4d1740485713a2ab3a4f5822a01f645fe8387f92",
                "52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c"
            };

            ResourcesHelper.ValidateResourcea(values, ResourceType.AnyHash);

            ResourcesHelper.ValidateResourcea("99017f6eebbac24f351415dd410d522d", ResourceType.MD5);
            ResourcesHelper.ValidateResourcea("4d1740485713a2ab3a4f5822a01f645fe8387f92", ResourceType.SHA1);
            ResourcesHelper.ValidateResourcea("52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c", ResourceType.SHA256);
            ResourcesHelper.ValidateResourcea("52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1273894724", ResourceType.ScanId);
            ResourcesHelper.ValidateResourcea("https://developers.virustotal.com/v2.0/reference#file-report", ResourceType.URL);
            ResourcesHelper.ValidateResourcea("http://google.com/?data=fake&nottrue=%20", ResourceType.URL);
            ResourcesHelper.ValidateResourcea("domainonly.com", ResourceType.URL);
        }

        [Fact]
        public void InvalidResources()
        {
            Assert.Throws<InvalidResourceException>(() => ResourcesHelper.ValidateResourcea("99017f6eebbac24f35-1415dd410d522d", ResourceType.AnyType));
            Assert.Throws<InvalidResourceException>(() => ResourcesHelper.ValidateResourcea("1r1", ResourceType.AnyType));
            Assert.Throws<InvalidResourceException>(() => ResourcesHelper.ValidateResourcea("", ResourceType.AnyType));
            Assert.Throws<InvalidResourceException>(() => ResourcesHelper.ValidateResourcea("52d3df0ed60c46f336c131bf-2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1273894724", ResourceType.AnyType));
            Assert.Throws<InvalidResourceException>(() => ResourcesHelper.ValidateResourcea("https://", ResourceType.AnyType));
            Assert.Throws<InvalidResourceException>(() => ResourcesHelper.ValidateResourcea("https:///google.com", ResourceType.AnyType));
        }
    }
}