# VirusTotal.NET - A full implementation of the VirusTotal 2.0 API

[![NuGet](https://img.shields.io/nuget/v/VirusTotalNet.svg?style=flat-square&label=nuget)](https://www.nuget.org/packages/VirusTotalNet/)

### Features

* Fully asynchronous API
* Scan, rescan and get reports of scanned files and URLs
* Get reports for IP addresses, URLs, and domains
* Batch support for APIs that support it
* Size and resource limits built in for better performance
* Configurable limits to accommodate some VT private API features. However, this API does not officially support the private VT API.

### Examples

```csharp
VirusTotal virusTotal = new VirusTotal("YOUR API KEY HERE");

//Use HTTPS instead of HTTP
virusTotal.UseTLS = true;

//Create the EICAR test virus. See http://www.eicar.org/86-0-Intended-use.html
byte[] eicar = Encoding.ASCII.GetBytes(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

//Check if the file has been scanned before.
FileReport report = await virusTotal.GetFileReportAsync(eicar);

Console.WriteLine("Seen before: " + (report.ResponseCode == FileReportResponseCode.Present ? "Yes" : "No"));
```

Output:
```
Seen before: True
```

Take a look at the VirusTotal.Examples project for more examples.