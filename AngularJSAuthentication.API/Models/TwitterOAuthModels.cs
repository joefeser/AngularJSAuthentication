using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace AngularJSAuthentication.API.Models
{
    public class TwitterUserSettings
    {
        //these are the only ones that we need.
        public long id { get; set; }
        public string screen_name { get; set; }
        public bool verified { get; set; }
    }
}