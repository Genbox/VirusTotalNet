using System;

namespace VirusTotalNet.Enums;

[Flags]
public enum ResourceType : long
{
    MD5 = 1 << 0,
    SHA1 = 1 << 1,
    SHA256 = 1 << 2,
    ScanId = 1 << 3,
    URL = 1 << 4,
    IP = 1 << 5,
    Domain = 1 << 6,
    AnyHash = MD5 | SHA1 | SHA256,
    AnyType = AnyHash | ScanId | URL | IP | Domain
}