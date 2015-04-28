using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace AngularJSAuthentication.API.Models
{
    public class TwitterOauthTokenResult
    {
        public TwitterOauthTokenResultMeta meta { get; set; }
        public InstagramOauthModelUser data { get; set; }
    }

    public class TwitterOauthTokenResultMeta
    {
        public string code { get; set; }
    }
}