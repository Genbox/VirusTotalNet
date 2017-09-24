using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using VirusTotalNET.Helpers;

namespace VirusTotalNET.UnitTests.TestInternals
{
    internal static class TestData
    {
        private static readonly Random _random = new Random();


        internal static readonly string[] KnownDomains = { "google.com", "facebook.com", "virustotal.com" };

        internal static readonly string[] KnownUrls = { "http://google.se", "http://google.com", "https://virustotal.com" };
        internal static readonly string[] KnownIPv4s = { "8.8.8.8", "8.8.4.4", "216.58.211.142" }; //Google DNS and Google.com
        internal static readonly string[] KnownHashes =
        {
            "bf531b602b823473f09c7102b3baabd1848bef03", //conficker
            "e1112134b6dcc8bed54e0e34d8ac272795e73d74", //fake AV
            "5b63d3bf46aec2126932d8a683ca971c56f7d717" //IRC bot
        };

        internal const string TestFileName = "VirusTotal.NET";
        internal static readonly byte[] TestFile = Encoding.ASCII.GetBytes("VirusTotal.NET test file");
        internal static readonly string TestHash = ResourcesHelper.GetResourceIdentifier(TestFile);

        /// <summary>
        /// EICAR test virus. See http://www.EICARMalware.org/86-0-Intended-use.html
        /// </summary>
        internal const string EICARFilename = "EICAR.txt";
        internal static readonly byte[] EICARMalware = Encoding.ASCII.GetBytes(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

        internal static IEnumerable<string> GetUnknownDomains(int count)
        {
            for (int i = 0; i < count; i++)
            {
                yield return $"VirusTotal.NET-{Guid.NewGuid()}.com";
            }
        }

        internal static IEnumerable<string> GetUnknownUrls(int count)
        {
            foreach (string unknownDomain in GetUnknownDomains(count))
            {
                yield return "http://" + unknownDomain;

            }
        }

        internal static IEnumerable<string> GetUnknownIPv4s(int count)
        {
            for (int i = 0; i < count; i++)
            {
                IPAddress d = new IPAddress(BitConverter.GetBytes(i).Reverse().ToArray());
                yield return d.ToString();
            }
        }

        internal static IEnumerable<string> GetRandomIPv6s(int count)
        {
            byte[] bytes = new byte[16];

            for (int i = 0; i < count; i++)
            {
                _random.NextBytes(bytes);
                IPAddress ipv6Address = new IPAddress(bytes);
                yield return ipv6Address.ToString();
            }
        }

        internal static IEnumerable<string> GetRandomSHA1s(int count)
        {
            byte[] bytes = new byte[20];

            for (int i = 0; i < count; i++)
            {
                _random.NextBytes(bytes);
                yield return HashHelper.ByteArrayToHex(bytes);
            }
        }

        internal static IEnumerable<byte[]> GetRandomFile(int size, int count)
        {
            for (int i = 0; i < count; i++)
            {
                byte[] bytes = new byte[size];
                _random.NextBytes(bytes);
                yield return bytes;
            }
        }
    }
}
