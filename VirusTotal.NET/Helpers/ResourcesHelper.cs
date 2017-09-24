using System;
using System.Collections.Generic;
using System.IO;
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

        public static IEnumerable<string> GetResourceIdentifier(IEnumerable<Uri> uris)
        {
            foreach (Uri uri in uris)
            {
                yield return GetResourceIdentifier(uri);
            }
        }

        public static string GetResourceIdentifier(Uri uri)
        {
            return HashHelper.GetSHA256(uri.ToString());
        }

        public static IEnumerable<string> GetResourceIdentifier(IEnumerable<string> urls)
        {
            foreach (string uri in urls)
            {
                yield return GetResourceIdentifier(uri);
            }
        }

        public static string GetResourceIdentifier(string url)
        {
            return GetResourceIdentifier(UrlToUri(url));
        }

        public static void ValidateResource(IEnumerable<string> resources, bool canBeUrl) //TODO
        {
            foreach (string resource in resources)
            {
                ValidateResource(resource, canBeUrl);
            }
        }

        public static void ValidateResource(string resource, bool canBeUrl) //TODO
        {
            if (string.IsNullOrWhiteSpace(resource))
                throw new ArgumentException("Resource must not be null or whitespace", nameof(resource));

            if (resource.Length != 32 && resource.Length != 40 && resource.Length != 64 && resource.Length != 75)
                throw new InvalidResourceException("Resource " + resource + " has to be either a MD5, SHA1, SHA256 or scan id");
        }

        public static IEnumerable<Uri> UrlToUri(IEnumerable<string> urls)
        {
            foreach (string url in urls)
            {
                Uri uri;
                try
                {
                    uri = UrlToUri(url);
                }
                catch (Exception ex)
                {
                    throw new Exception("There was an error converting " + url + " to an URI. See InnerException for details.", ex);
                }

                yield return uri;
            }
        }

        public static Uri UrlToUri(string url)
        {
            string tempUri = url.Trim();
            string lowered = tempUri.ToLower();

            if (!lowered.StartsWith("http://") && !lowered.StartsWith("https://"))
                tempUri = "http://" + tempUri;

            return new Uri(tempUri);
        }
    }
}
