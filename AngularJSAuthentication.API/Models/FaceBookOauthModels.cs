using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace AngularJSAuthentication.API.Models
{
    public class FacebookDebugErrorResult
    {
        public FacebookDebugErrorResultMessage error { get; set; }
    }

    public class FacebookDebugErrorResultMessage
    {
        public string message { get; set; }
        public string type { get; set; }
        public int code { get; set; }
    }

    public class FacebookDebugResult
    {
        public FacebookDebugResultData data { get; set; }
    }

    public class FacebookDebugResultError
    {
        public int code { get; set; }
        public string message { get; set; }
        public int subcode { get; set; }
    }

    public class FacebookDebugResultData
    {
        public long app_id { get; set; }
        public string application { get; set; }
        public FacebookDebugResultError error { get; set; }
        public long expires_at { get; set; }
        public bool is_valid { get; set; }
        public long issued_at { get; set; }
        public List<string> scopes { get; set; }
        public long user_id { get; set; }
    }
}