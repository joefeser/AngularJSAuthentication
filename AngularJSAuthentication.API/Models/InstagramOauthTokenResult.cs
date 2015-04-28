using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace AngularJSAuthentication.API.Models
{
    public class InstagramOauthTokenResult
    {
        public InstagramOauthTokenResultMeta meta { get; set; }
        public InstagramOauthModelUser data { get; set; }
    }

    public class InstagramOauthTokenResultMeta
    {
        public string code { get; set; }
    }
}