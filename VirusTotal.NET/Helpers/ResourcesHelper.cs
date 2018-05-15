using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using VirusTotalNET.Enums;
using VirusTotalNET.Exceptions;

namespace VirusTotalNET.Helpers
{
    public static class ResourcesHelper
    {
        public static IEnumerable<string> GetResourceIdentifier(IEnumerable<FileInfo> files)
        {
            foreach (FileInfo fileInfo in files)
            {
                yield return GetResourceIdentifier(fileInfo);
            }
        }

        public static string GetResourceIdentifier(FileInfo file)
        {
            return HashHelper.GetSHA256(file);
        }

        public static IEnumerable<string> GetResourceIdentifier(IEnumerable<byte[]> files)
        {
            foreach (byte[] fileBytes in files)
            {
                yield return GetResourceIdentifier(fileBytes);
            }
        }

        public static string GetResourceIdentifier(byte[] file)
        {
            return HashHelper.GetSHA256(file);
        }

        public static IEnumerable<string> GetResourceIdentifier(IEnumerable<Stream> streams)
        {
            foreach (Stream stream in streams)
            {
                yield return GetResourceIdentifier(stream);
            }
        }

        public static string GetResourceIdentifier(Stream stream)
        {
            return HashHelper.GetSHA256(stream);
        }

        public static string GetResourceIdentifier(string url)
        {
            if (!IsValidURL(url, out url))
                throw new InvalidResourceException($"The url '{url}' is in the wrong format");

            return HashHelper.GetSHA256(url);
        }

        public static string GetResourceIdentifier(Uri url)
        {
            return GetResourceIdentifier(url.ToString());
        }

        public static IEnumerable<string> ValidateResourcea(IEnumerable<string> resources, ResourceType type)
        {
            if (resources == null)
                throw new InvalidResourceException("No resources given");

            IEnumerable<string> array = resources as string[] ?? resources.ToArray();

            if (!array.Any())
                throw new InvalidResourceException("No resources given");

            foreach (string resource in array)
            {
                yield return ValidateResourcea(resource, type);
            }
        }

        public static string ValidateResourcea(string resource, ResourceType type)
        {
            if (string.IsNullOrWhiteSpace(resource))
                throw new InvalidResourceException("Resource is invalid");

            string sanitized = resource;
            bool valid = false;

            if (type.HasFlag(ResourceType.MD5))
                valid |= IsValidMD5(resource);
            if (type.HasFlag(ResourceType.SHA1))
                valid |= IsValidSHA1(resource);
            if (type.HasFlag(ResourceType.SHA256))
                valid |= IsValidSHA256(resource);
            if (type.HasFlag(ResourceType.ScanId))
                valid |= IsValidScanId(resource);
            if (type.HasFlag(ResourceType.URL))
                valid |= IsValidURL(resource, out sanitized);
            if (type.HasFlag(ResourceType.IP))
                valid |= IsValidIP(resource, out sanitized);
            if (type.HasFlag(ResourceType.Domain))
                valid |= IsValidDomain(resource, out sanitized);

            if (!valid)
                throw new InvalidResourceException($"Resource '{resource}' has to be one of the following: {string.Join(", ", type.GetIndividualFlags())}");

            return sanitized;
        }

        public static bool IsValidScanId(string resource)
        {
            if (resource.Length != 75)
                return false;

            string[] parts = resource.Split('-');

            if (parts.Length != 2)
                return false;

            if (parts[0].Length != 64 || parts[1].Length != 10)
                return false;

            return IsAlphaNumeric(parts[0]) && IsNumeric(parts[1]);
        }

        public static bool IsValidURL(string resource, out string sanitized)
        {
            sanitized = resource;

            if (!resource.Contains('.'))
                return false;

            if (!Uri.TryCreate(NormalizeUrl(resource, false), UriKind.Absolute, out Uri uri))
                return false;

            sanitized = uri.ToString();
            return true;
        }

        public static bool IsValidIP(string resource, out string sanitized)
        {
            sanitized = resource;

            if (!IPAddress.TryParse(resource, out IPAddress ip))
                return false;

            if (ip.AddressFamily != AddressFamily.InterNetwork)
                return false;

            sanitized = ip.ToString();
            return true;
        }

        public static bool IsValidDomain(string resource, out string sanitized)
        {
            sanitized = resource;

            if (!resource.Contains('.'))
                return false;

            if (!Uri.TryCreate(NormalizeUrl(resource, false), UriKind.Absolute, out Uri uri))
                return false;

            sanitized = uri.Host;
            return true;
        }

        public static bool IsValidMD5(string resource)
        {
            return resource.Length == 32 && IsAlphaNumeric(resource);
        }

        public static bool IsValidSHA1(string resource)
        {
            return resource.Length == 40 && IsAlphaNumeric(resource);
        }

        public static bool IsValidSHA256(string resource)
        {
            return resource.Length == 64 && IsAlphaNumeric(resource);
        }

        public static bool IsAlphaNumeric(string input)
        {
            return input.All(char.IsLetterOrDigit);
        }

        public static bool IsNumeric(string input)
        {
            return input != string.Empty && input.All(x => x >= 48 && x <= 57);
        }

        public static string NormalizeUrl(string url, bool useTls)
        {
            string tempUri = url.Trim();

            if (tempUri.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || tempUri.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                return tempUri;

            if (useTls)
            {
                if (!tempUri.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                    tempUri = "https://" + tempUri;
            }
            else
            {
                if (!tempUri.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                    tempUri = "http://" + tempUri;
            }

            return tempUri;
        }
    }
}