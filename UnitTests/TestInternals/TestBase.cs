using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace VirusTotalNET.UnitTests.TestInternals
{
    //This code comes from https://github.com/LordMike/TMDbLib/blob/master/TMDbLibTests/JsonHelpers/TestBase.cs

    public abstract class TestBase : IDisposable
    {
        private static readonly Regex _normalizeRegex = new Regex(@"\[[\d]+\]", RegexOptions.Compiled);
        private readonly List<ErrorEventArgs> _errors = new List<ErrorEventArgs>();
        private readonly List<string> _ignoreMissingCSharp;
        private readonly List<string> _ignoreMissingJson;

        protected TestBase()
        {
            _ignoreMissingJson = new List<string>();
            _ignoreMissingCSharp = new List<string>();

            ThrowOnMissingContract = true;

            JsonSerializerSettings settings = new JsonSerializerSettings();
            settings.MissingMemberHandling = MissingMemberHandling.Error;
            settings.ContractResolver = new FailingContractResolver();
            settings.Error = Error;

            VirusTotal = new VirusTotal("YOUR API KEY HERE", settings);
            VirusTotal.UserAgent = "VirusTotal.NET unit tests";
            VirusTotal.UseTLS = false;
            
            VirusTotal.OnRawResponseReceived += bytes =>
            {
                LastCallInJSON = Encoding.UTF8.GetString(bytes);
            };

            //Hack to only make 4 requests pr. sec. with public API key
            if (!Debugger.IsAttached)
                Thread.Sleep(15000);
        }

        protected VirusTotal VirusTotal { get; }

        protected bool ThrowOnMissingContract { get; set; }

        protected string LastCallInJSON { get; set; }

        /// <summary>
        /// Ignores errors about missing JSON properties (Where C# properties are not set)
        /// </summary>
        protected void IgnoreMissingJson(params string[] keys)
        {
            _ignoreMissingJson.AddRange(keys);
        }

        /// <summary>
        /// Ignores errors about missing C# properties (Where new or unknown JSON properties are present)
        /// </summary>
        protected void IgnoreMissingCSharp(params string[] keys)
        {
            _ignoreMissingCSharp.AddRange(keys);
        }

        private void Error(object sender, ErrorEventArgs errorEventArgs)
        {
            _errors.Add(errorEventArgs);
            errorEventArgs.ErrorContext.Handled = true;
        }

        public void Dispose()
        {
            if (!_errors.Any())
                return;

            // Sort the errors
            // Also de-duplicate them, as there is no point in blasting us with multiple instances of the "same" error
            Dictionary<string, ErrorEventArgs> missingFieldInCSharp = new Dictionary<string, ErrorEventArgs>();
            Dictionary<string, ErrorEventArgs> missingPropertyInJson = new Dictionary<string, ErrorEventArgs>();
            Dictionary<string, ErrorEventArgs> other = new Dictionary<string, ErrorEventArgs>();

            foreach (ErrorEventArgs error in _errors)
            {
                string key = error.ErrorContext.Path + " / " + error.ErrorContext.Member;
                string errorMessage = error.ErrorContext.Error.Message;

                key = _normalizeRegex.Replace(key, "[array]");

                if (errorMessage.StartsWith("Could not find member"))
                {
                    // Field in JSON is missing in C#
                    if (!_ignoreMissingCSharp.Contains(key) && !missingFieldInCSharp.ContainsKey(key))
                        missingFieldInCSharp.Add(key, error);
                }
                else if (errorMessage.StartsWith("Required property"))
                {
                    // Field in C# is missing in JSON
                    if (!_ignoreMissingJson.Contains(key) && !missingPropertyInJson.ContainsKey(key))
                        missingPropertyInJson.Add(key, error);
                }
                else
                {
                    if (!other.ContainsKey(key))
                        other.Add(key, error);
                }
            }

            // Combine all errors into a nice text
            StringBuilder sb = new StringBuilder();

            if (missingFieldInCSharp.Any())
            {
                sb.AppendLine("Fields missing in C# (Present in JSON)");
                foreach (KeyValuePair<string, ErrorEventArgs> pair in missingFieldInCSharp)
                    sb.AppendLine($"[{pair.Value.CurrentObject.GetType().Name}] {pair.Key}: {pair.Value.ErrorContext.Error.Message}");

                sb.AppendLine();
            }

            if (missingPropertyInJson.Any())
            {
                sb.AppendLine("Fields missing in JSON (Present in C#)");
                foreach (KeyValuePair<string, ErrorEventArgs> pair in missingPropertyInJson)
                    sb.AppendLine($"[{pair.Value.CurrentObject.GetType().Name}] {pair.Key}: {pair.Value.ErrorContext.Error.Message}");

                sb.AppendLine();
            }

            if (other.Any())
            {
                sb.AppendLine("Other errors");
                foreach (KeyValuePair<string, ErrorEventArgs> pair in other)
                    sb.AppendLine($"[{pair.Value.CurrentObject.GetType().Name}] {pair.Key}: {pair.Value.ErrorContext.Error.Message}");

                sb.AppendLine();
            }

            if (missingFieldInCSharp.Any())
            {
                // Helper line of properties that can be ignored
                sb.AppendLine("Ignore JSON props missing from C#:");
                sb.AppendLine(nameof(IgnoreMissingCSharp) + "(" + string.Join(", ", missingFieldInCSharp.OrderBy(s => s.Key).Select(s => $"\"{s.Key}\"")) + ");");

                sb.AppendLine();
            }

            if (missingPropertyInJson.Any())
            {
                // Helper line of properties that can be ignored
                sb.AppendLine("Ignore C# props missing from JSON:");
                sb.AppendLine(nameof(IgnoreMissingJson) + "(" + string.Join(", ", missingPropertyInJson.OrderBy(s => s.Key).Select(s => $"\"{s.Key}\"")) + ");");

                sb.AppendLine();
            }

            if (!ThrowOnMissingContract)
                return;

            if (missingFieldInCSharp.Any() || missingPropertyInJson.Any() || other.Any())
                throw new Exception(sb + Environment.NewLine + "Raw JSON: " + Environment.NewLine + LastCallInJSON);
        }
    }
}