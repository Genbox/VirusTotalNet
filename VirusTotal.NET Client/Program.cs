using System;
using System.Configuration;
using System.IO;
using VirusTotalNET;
using VirusTotalNET.Objects;

namespace VirusTotalNETClient
{
    class Program
    {
        private const string ScanUrl = "http://www.google.com/";

        static void Main(string[] args)
        {
            VirusTotal virusTotal = new VirusTotal(ConfigurationManager.AppSettings["ApiKey"]);

            //Use HTTPS instead of HTTP
            virusTotal.UseTLS = true;

            //Create the EICAR test virus. See http://www.eicar.org/86-0-Intended-use.html
            FileInfo fileInfo = new FileInfo("EICAR.txt");
            File.WriteAllText(fileInfo.FullName, @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

            //Check if the file has been scanned before.
            Report fileReport = virusTotal.GetFileReport(fileInfo);

            bool hasFileBeenScannedBefore = fileReport.ResponseCode == 1;

            Console.WriteLine("File has been scanned before: " + (hasFileBeenScannedBefore ? "Yes" : "No"));

            //If the file has been scanned before, the results are embedded inside the report.
            if (hasFileBeenScannedBefore)
            {
                PrintScan(fileReport);
            }
            else
            {
                ScanResult fileResult = virusTotal.ScanFile(fileInfo);
                PrintScan(fileResult);
            }

            Console.WriteLine();

            Report urlReport = virusTotal.GetUrlReport(ScanUrl);

            bool hasUrlBeenScannedBefore = urlReport.ResponseCode == 1;
            Console.WriteLine("URL has been scanned before: " + (hasUrlBeenScannedBefore ? "Yes" : "No"));

            //If the url has been scanned before, the results are embedded inside the report.
            if (hasUrlBeenScannedBefore)
            {
                PrintScan(urlReport);
            }
            else
            {
                ScanResult urlResult = virusTotal.ScanUrl(ScanUrl);
                PrintScan(urlResult);
            }

            Console.WriteLine("Press a key to continue");
            Console.ReadLine();
        }

        private static void PrintScan(ScanResult scanResult)
        {
            Console.WriteLine("Scan ID: " + scanResult.ScanId);
            Console.WriteLine("Message: " + scanResult.VerboseMsg);
            Console.WriteLine();
        }

        private static void PrintScan(Report report)
        {
            Console.WriteLine("Scan ID: " + report.ScanId);
            Console.WriteLine("Message: " + report.VerboseMsg);

            if (report.ResponseCode == 1)
            {
                foreach (ScanEngine scan in report.Scans)
                {
                    Console.WriteLine("{0,-25} Detected: {1}", scan.Name, scan.Detected);
                }
            }

            Console.WriteLine();
        }
    }
}