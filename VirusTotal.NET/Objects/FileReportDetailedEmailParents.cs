// Copyright Keith J. Jones © 2016

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using RestSharp.Deserializers;


namespace VirusTotalNET.Objects
{
    public class FileReportDetailedEmailParents
    {
        public string Message { get; set; }

        [DeserializeAs(Name = "message_id")]
        public string MessageID { get; set; }
        public string Receiver { get; set; }
        public string Sender { get; set; }
        public string Subject { get; set; }
    }
}
