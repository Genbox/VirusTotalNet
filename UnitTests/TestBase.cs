using VirusTotalNET;

namespace UnitTests
{
    public abstract class TestBase
    {
        public VirusTotal VirusTotal { get; } = new VirusTotal("YOUR API KEY HERE");
    }
}
