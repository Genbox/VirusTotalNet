# VirusTotal.NET - A full implementation of the VirusTotal 2.0 API

### Features

* Based on RestSharp (http://restsharp.org) to deserialize the VirusTotal JSON into objects
* Scan, rescan and get report of scanned files
* Scan websites and files
* Support for HTTP and HTTPS
* Support for checking if files have been scanned before

### Examples

Here is the simplest form of getting data from VirusTotal:

```csharp
static void Main(string[] args)
{
    VirusTotal virusTotal = new VirusTotal("INSERT API KEY HERE");

    //Use HTTPS instead of HTTP
    virusTotal.UseTLS = true;

    FileInfo fileInfo = new FileInfo("testfile.txt");

    //Create a new file
    File.WriteAllText(fileInfo.FullName, "This is a test file!");

	 //Check if the file has been scanned before.
	Report fileReport = virusTotal.GetFileReport(fileInfo).First();
	bool hasFileBeenScannedBefore = fileReport.ResponseCode == 1;

    if (hasFileBeenScannedBefore)
    {
        Console.WriteLine(fileReport.ScanId);
    }
    else
    {
        ScanResult fileResults = virusTotal.ScanFile(fileInfo);
		Console.WriteLine(fileResults.VerboseMsg);
    }
}
```

Output:
```
File has been scanned before: True
Scan finished, scan information embedded in this object
```

For more examples, take a look at the VirusTotal.NET Client included in the project.

### Contributors
@keithjjones
