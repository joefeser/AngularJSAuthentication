﻿using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace AngularJSAuthentication.API.Models
{
    public class ExternalLoginViewModel
    {
        public string Name { get; set; }

        public string Url { get; set; }

        public string State { get; set; }
    }

    public class ObtainLocalAccessTokenModel
    {

        [Required]
        public string Provider { get; set; }

        [Required]
        public string ExternalAccessToken { get; set; }

        //[Required]
        //needed for Twitter.
        public string ExternalAccessSecretToken { get; set; }
    }

    public class RegisterExternalBindingModel
    {
        [Required]
        public string UserName { get; set; }

        [Required]
        public string Provider { get; set; }

        [Required]
        public string ExternalAccessToken { get; set; }

        //[Required]
        //needed for Twitter.
        public string ExternalAccessSecretToken { get; set; }
    }

    public class ParsedExternalAccessToken
    {
        public string user_id { get; set; }
        public string screen_name { get; set; } //twitter
        public string app_id { get; set; }
        public bool valid { get; set; }
        public int code { get; set; }
        public int subcode { get; set; }
        public string token { get; set; }
    }
}