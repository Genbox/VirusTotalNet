using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace VirusTotalNET.Helpers
{
    public static class HashHelper
    {
        public static string GetSHA256(byte[] buffer)
        {
            using (MemoryStream ms = new MemoryStream(buffer))
                return GetSHA256(ms);
        }

        public static string GetSHA256(string content)
        {
            return GetSHA256(content, Encoding.UTF8);
        }

        public static string GetSHA256(string content, Encoding encoding)
        {
            using (MemoryStream ms = new MemoryStream(encoding.GetBytes(content)))
                return GetSHA256(ms);
        }

        public static string GetSHA256(FileInfo file)
        {
            if (!file.Exists)
                throw new FileNotFoundException("File not found.", file.FullName);

            using (FileStream stream = file.OpenRead())
                return GetSHA256(stream);
        }

        public static string GetSHA256(Stream stream)
        {
            if (stream == null || stream.Length == 0)
                throw new ArgumentException("You must provide a valid stream.", nameof(stream));

            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(stream);
                return ByteArrayToHex(hashBytes);
            }
        }

        public static string GetSHA1(byte[] buffer)
        {
            using (MemoryStream ms = new MemoryStream(buffer))
                return GetSHA1(ms);
        }

        public static string GetSHA1(string content)
        {
            return GetSHA1(content, Encoding.UTF8);
        }

        public static string GetSHA1(string content, Encoding encoding)
        {
            using (MemoryStream ms = new MemoryStream(encoding.GetBytes(content)))
                return GetSHA1(ms);
        }

        public static string GetSHA1(FileInfo file)
        {
            if (!file.Exists)
                throw new FileNotFoundException("File not found.", file.FullName);

            using (FileStream stream = file.OpenRead())
                return GetSHA1(stream);
        }

        public static string GetSHA1(Stream stream)
        {
            if (stream == null || stream.Length == 0)
                throw new ArgumentException("You must provide a valid stream.", nameof(stream));

            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] hashBytes = sha1.ComputeHash(stream);
                return ByteArrayToHex(hashBytes);
            }
        }

        public static string GetMD5(byte[] buffer)
        {
            using (MemoryStream ms = new MemoryStream(buffer))
                return GetMD5(ms);
        }

        public static string GetMD5(string content)
        {
            return GetMD5(content, Encoding.UTF8);
        }

        public static string GetMD5(string content, Encoding encoding)
        {
            using (MemoryStream ms = new MemoryStream(encoding.GetBytes(content)))
                return GetMD5(ms);
        }

        public static string GetMD5(FileInfo file)
        {
            if (!file.Exists)
                throw new FileNotFoundException("File not found.", file.FullName);

            using (FileStream stream = file.OpenRead())
                return GetMD5(stream);
        }

        public static string GetMD5(Stream stream)
        {
            if (stream == null || stream.Length == 0)
                throw new ArgumentException("You must provide a valid stream.", nameof(stream));

            using (MD5 md5 = MD5.Create())
            {
                byte[] md5Result = md5.ComputeHash(stream);
                return ByteArrayToHex(md5Result);
            }
        }

        public static string ByteArrayToHex(byte[] buffer)
        {
            StringBuilder hex = new StringBuilder(buffer.Length * 2);
            foreach (byte b in buffer)
                hex.AppendFormat("{0:x2}", b);

            return hex.ToString();
        }
    }
}