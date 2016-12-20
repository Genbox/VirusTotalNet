# VirusTotal.NET - A full implementation of the VirusTotal 2.0 API

### Features

* Fully ayncronous API
* Scan, rescan and get report of scanned files
* Scan websites and files
* Support for HTTP and HTTPS
* Support IP and domain reports

### Examples

```csharp
VirusTotal virusTotal = new VirusTotal("YOUR API KEY HERE");

//Use HTTPS instead of HTTP
virusTotal.UseTLS = true;

//Create the EICAR test virus. See http://www.eicar.org/86-0-Intended-use.html
File.WriteAllText("EICAR.txt", @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

//Check if the file has been scanned before.
FileReport report = await virusTotal.GetFileReport(new FileInfo("EICAR.txt");

Console.WriteLine("Seen before: " + (report.ResponseCode == ReportResponseCode.Present ? "Yes" : "No"));
```

Output:
```
Seen before: True
```

For more examples, take a look at the VirusTotal.NET Client included in the project.

### Contributors
[keithjjones](https://github.com/keithjjones)
