using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace VirusTotalNet.Helpers;

public static class HashHelper
{
    public static string GetSha256(byte[] buffer)
    {
        using MemoryStream ms = new MemoryStream(buffer);
        return GetSha256(ms);
    }

    public static string GetSha256(string content, Encoding? encoding = null)
    {
        encoding ??= Encoding.UTF8;

        using MemoryStream ms = new MemoryStream(encoding.GetBytes(content));
        return GetSha256(ms);
    }

    public static string GetSha256(FileInfo file)
    {
        if (!file.Exists)
            throw new FileNotFoundException("File not found.", file.FullName);

        using FileStream stream = file.OpenRead();
        return GetSha256(stream);
    }

    public static string GetSha256(Stream stream)
    {
        if (stream == null || stream.Length == 0)
            throw new ArgumentException("You must provide a valid stream.", nameof(stream));

        using SHA256 sha256 = SHA256.Create();
        byte[] hashBytes = sha256.ComputeHash(stream);
        return ByteArrayToHex(hashBytes);
    }

    public static string GetSha1(byte[] buffer)
    {
        using MemoryStream ms = new MemoryStream(buffer);
        return GetSha1(ms);
    }

    public static string GetSha1(string content, Encoding? encoding = null)
    {
        encoding ??= Encoding.UTF8;

        using MemoryStream ms = new MemoryStream(encoding.GetBytes(content));
        return GetSha1(ms);
    }

    public static string GetSha1(FileInfo file)
    {
        if (!file.Exists)
            throw new FileNotFoundException("File not found.", file.FullName);

        using FileStream stream = file.OpenRead();
        return GetSha1(stream);
    }

    public static string GetSha1(Stream stream)
    {
        if (stream == null || stream.Length == 0)
            throw new ArgumentException("You must provide a valid stream.", nameof(stream));

        using SHA1 sha1 = SHA1.Create();
        byte[] hashBytes = sha1.ComputeHash(stream);
        return ByteArrayToHex(hashBytes);
    }

    public static string GetMd5(byte[] buffer)
    {
        using MemoryStream ms = new MemoryStream(buffer);
        return GetMd5(ms);
    }

    public static string GetMd5(string content, Encoding? encoding = null)
    {
        encoding ??= Encoding.UTF8;

        using MemoryStream ms = new MemoryStream(encoding.GetBytes(content));
        return GetMd5(ms);
    }

    public static string GetMd5(FileInfo file)
    {
        if (!file.Exists)
            throw new FileNotFoundException("File not found.", file.FullName);

        using FileStream stream = file.OpenRead();
        return GetMd5(stream);
    }

    public static string GetMd5(Stream stream)
    {
        if (stream == null || stream.Length == 0)
            throw new ArgumentException("You must provide a valid stream.", nameof(stream));

        using MD5 md5 = MD5.Create();
        byte[] md5Result = md5.ComputeHash(stream);
        return ByteArrayToHex(md5Result);
    }

    public static string ByteArrayToHex(byte[] buffer)
    {
        StringBuilder hex = new StringBuilder(buffer.Length * 2);

        foreach (byte b in buffer)
            hex.AppendFormat("{0:x2}", b);

        return hex.ToString();
    }
}