using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace VirusTotalNET
{
    public static class HashHelper
    {
        public static string GetSHA256(string content)
        {
            return GetSHA256(Encoding.ASCII.GetBytes(content));
        }

        public static string GetSHA256(byte[] buffer)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(buffer);
                return ByteArrayToString(hashBytes);
            }
        }

        public static string GetSHA256(FileInfo file)
        {
            if (!file.Exists)
                throw new FileNotFoundException("File not found.", file.FullName);

            byte[] buffer = File.ReadAllBytes(file.FullName);
            return GetSHA256(buffer);
        }

        public static string GetMD5(string content)
        {
            return GetMD5(Encoding.ASCII.GetBytes(content));
        }

        public static string GetMD5(FileInfo file)
        {
            if (!file.Exists)
                throw new FileNotFoundException("File not found.", file.FullName);

            byte[] buffer = File.ReadAllBytes(file.FullName);
            return GetMD5(buffer);
        }

        public static string GetMD5(byte[] buffer)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] md5Result = md5.ComputeHash(buffer);
                return ByteArrayToString(md5Result);
            }
        }

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);

            return hex.ToString();
        }
    }
}