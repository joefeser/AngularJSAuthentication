using AngularJSAuthentication.API.Models;
using Microsoft.AspNet.Identity;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;

namespace AngularJSAuthentication.API.Providers
{
    public class InstagramAuthenticationHandler : BaseAuthenticationHandler
    {
        public async Task<ParsedExternalAccessToken> ObtainCredentialInformationAsync(string userToken)
        {
            var parameters = new List<KeyValuePair<string, string>>();

            parameters.Add(new KeyValuePair<string, string>("client_id", ConfigurationManager.AppSettings["instagram_appid"].ToString()));
            parameters.Add(new KeyValuePair<string, string>("client_secret", ConfigurationManager.AppSettings["instagram_appsecret"].ToString()));
            parameters.Add(new KeyValuePair<string, string>("grant_type", "authorization_code"));
            parameters.Add(new KeyValuePair<string, string>("redirect_uri", ConfigurationManager.AppSettings["instagram_redirecturl"].ToString()));
            parameters.Add(new KeyValuePair<string, string>("code", userToken));

            var formData = new FormUrlEncodedContent(parameters);

            var resultData = await MakeHttpPostWithRetry("https://api.instagram.com/oauth/access_token", formData);

            // deserializing nested JSON string to object

            var accessTokenResult = JsonConvert.DeserializeObject<InstagramOauthModel>(resultData.Response);

            if (accessTokenResult != null && !string.IsNullOrWhiteSpace(accessTokenResult.access_token))
            {
                string accessToken = accessTokenResult.access_token;

                int id = int.Parse(accessTokenResult.user.id);

                var retVal = new ParsedExternalAccessToken()
                {
                    app_id = "0",
                    screen_name = accessTokenResult.user.username,
                    token = accessToken,
                    user_id = id.ToString(),
                    valid = true
                };
                return retVal;
            }

            resultData = await MakeHttpCallWithRetry("https://api.instagram.com/v1/users/self/?access_token=" + userToken);
            var userDataResult = JsonConvert.DeserializeObject<InstagramOauthTokenResult>(resultData.Response);

            if (userDataResult != null && userDataResult.data != null && !string.IsNullOrWhiteSpace(userDataResult.data.username))
            {
                int id = int.Parse(userDataResult.data.id);

                var retVal = new ParsedExternalAccessToken()
                {
                    app_id = "0",
                    screen_name = userDataResult.data.username,
                    token = userToken,
                    user_id = id.ToString(),
                    valid = true
                };
                return retVal;
            }
            return new ParsedExternalAccessToken();

        }
    }
}