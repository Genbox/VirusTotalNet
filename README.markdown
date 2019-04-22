# VirusTotal.NET - A full implementation of the VirusTotal 2.0 API

### Features

* Fully asynchronous API
* Scan, rescan and get reports of scanned files
* Scan URLs
* Get reports for IP addresses, URLs, and domains
* Support for HTTP and HTTPS
* Batch support for APIs that support it
* Size and resource limits built in for better performance
* Configurable limits to accommodate VT private API features
* See https://developers.virustotal.com/reference for the VT API documentation

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

For more examples, take a look at the VirusTotal.NET Client included in the project.

### Contributors
* [keithjjones](https://github.com/keithjjones)
* [ivandrofly](https://github.com/ivandrofly)
