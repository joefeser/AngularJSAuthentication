using AngularJSAuthentication.API.Models;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace AngularJSAuthentication.API.Providers
{
    public class FacebookAuthenticationHandler : BaseAuthenticationHandler
    {
        private static string access_token = null; //We use this to verify the user token and ask for a long token.

        public async Task<ParsedExternalAccessToken> VerifyFacebookAccessToken(string accessToken)
        {
            ParsedExternalAccessToken parsedToken = null;

            var verifyTokenEndPoint = "";

            var appToken = await EnsureFacebookAppToken();

            //The token should never expire once we have it
            //http://www.quora.com/Do-OAuth-app-access-tokens-in-Facebook-ever-expire-not-talking-about-user-access-tokens
            //You can get it from here: https://developers.facebook.com/tools/accesstoken/
            //More about debug_tokn here: http://stackoverflow.com/questions/16641083/how-does-one-get-the-app-access-token-for-debug-token-inspection-on-facebook
            verifyTokenEndPoint = string.Format("https://graph.facebook.com/debug_token?input_token={0}&access_token={1}", accessToken, appToken);

            var response = await MakeHttpCallWithRetry(verifyTokenEndPoint);

            if (response.Message.IsSuccessStatusCode)
            {
                var content = response.Response;
                parsedToken = new ParsedExternalAccessToken();

                var fbToken = Newtonsoft.Json.JsonConvert.DeserializeObject<FacebookDebugResult>(content);
                parsedToken.user_id = fbToken.data.user_id.ToString();
                parsedToken.app_id = fbToken.data.app_id.ToString();

                if (fbToken.data != null && fbToken.data.error != null)
                {
                    //we have an issue, most likely we did not get an auth.
                    parsedToken.code = fbToken.data.error.code;
                    //subcode 458 is app was not authorized.
                    //subcode 460 is Error validating access token: Session does not match current stored session.
                    //This may be because the user changed the password since the time the session was created or Facebook has changed the session for security reasons 
                    parsedToken.subcode = fbToken.data.error.subcode;
                }
                if (!string.Equals(Startup.facebookAuthOptions.AppId, parsedToken.app_id, StringComparison.OrdinalIgnoreCase))
                {
                    return null;
                }
                parsedToken.valid = true;

                //now we want to go get the long life token

                //go get the long token
                verifyTokenEndPoint = string.Format("https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id={0}&client_secret={1}&fb_exchange_token={2}",
                    ConfigurationManager.AppSettings["fbapp_appid"], ConfigurationManager.AppSettings["fbapp_appsecret"], accessToken);

                response = await MakeHttpCallWithRetry(verifyTokenEndPoint);

                if (response.Message.IsSuccessStatusCode)
                {
                    var kv = ParseIntoKeyValues(response.Response);
                    var foundKey = kv.FirstOrDefault(item => item.Key == "access_token");
                    parsedToken.token = foundKey.Value;
                }
            }
            else
            {
                var content = response.Response;
                var fbToken = Newtonsoft.Json.JsonConvert.DeserializeObject<FacebookDebugErrorResult>(content);

                //TODO Log. We may want to refresh the token depending on the error and then retry.

                return null;
            }

            return parsedToken;
        }

        private async Task<string> EnsureFacebookAppToken()
        {
            if (!string.IsNullOrWhiteSpace(access_token))
            {
                return access_token;
            }
            var endPoint = string.Format("https://graph.facebook.com/oauth/access_token?client_id={0}&client_secret={1}&grant_type=client_credentials",
                ConfigurationManager.AppSettings["fbapp_appid"], ConfigurationManager.AppSettings["fbapp_appsecret"]);
            var result = await MakeHttpCallWithRetry(endPoint);

            if (result.Response.Contains("access_token="))
            {
                var token = result.Response.Replace("access_token=", string.Empty);
                access_token = token;
                return access_token;
            }
            return null;
        }


    }
}