using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using VirusTotalNET;
using VirusTotalNET.Objects;

namespace VirusTotalNETClient
{
    class Program
    {
        static void Main(string[] args)
        {
            VirusTotal virusTotal = new VirusTotal(ConfigurationManager.AppSettings["ApiKey"]);

            //Use HTTPS instead of HTTP
            virusTotal.UseTLS = true;

            FileInfo fileInfo = new FileInfo("testfile.txt");

            //Create a new file
            File.WriteAllText(fileInfo.FullName, "This is a test file!");

            //Check if the file has been scanned before.
            Report fileReport = virusTotal.GetFileReport(fileInfo).First();

            bool hasFileBeenScannedBefore = fileReport.ResponseCode == 1;

            Console.WriteLine("File has been scanned before: " + (hasFileBeenScannedBefore ? "Yes" : "No"));

            if (hasFileBeenScannedBefore)
            {
                //Get the latest report of the file
                List<Report> fileReports = virusTotal.GetFileReport(HashHelper.GetMD5(fileInfo));
                fileReports.ForEach(PrintScan);
            }
            else
            {
                ScanResult fileResult = virusTotal.ScanFile(fileInfo);
                PrintScan(fileResult);
            }

            Console.WriteLine();

            const string url = "http://www.google.com/";

            Report urlReport = virusTotal.GetUrlReport(url).First();

            bool hasUrlBeenScannedBefore = urlReport.ResponseCode == 1;
            Console.WriteLine("URL has been scanned before: " + (hasUrlBeenScannedBefore ? "Yes" : "No"));

            if (hasUrlBeenScannedBefore)
            {
                //Get the latest report of the file
                List<Report> urlReports = virusTotal.GetUrlReport(url);
                urlReports.ForEach(PrintScan);
            }
            else
            {
                List<ScanResult> urlResults = virusTotal.ScanUrl(url);
                urlResults.ForEach(PrintScan);
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