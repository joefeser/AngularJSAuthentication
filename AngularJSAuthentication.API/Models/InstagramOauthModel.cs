using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace AngularJSAuthentication.API.Models
{
    public class InstagramOauthModel
    {
        public string access_token { get; set; }
        public InstagramOauthModelUser user { get; set; }
    }

    public class InstagramOauthModelUser
    {
        public string bio { get; set; }
        public string full_name { get; set; }
        public string id { get; set; }
        public string profile_picture { get; set; }
        public string username { get; set; }
        public string website { get; set; }
    }
}