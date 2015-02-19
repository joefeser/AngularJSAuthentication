using AngularJSAuthentication.API.Models;
using AngularJSAuthentication.API.Providers;
using AngularJSAuthentication.API.Results;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Helpers;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;

namespace AngularJSAuthentication.API.Controllers
{
    [RoutePrefix("api/Account")]
    public class AccountController : ApiController
    {
        private static string access_token = null; //We use this to verify the user token and ask for a long token.
        private AuthRepository _repo = null;

        private IAuthenticationManager Authentication
        {
            get { return Request.GetOwinContext().Authentication; }
        }

        public AccountController()
        {
            _repo = new AuthRepository();
        }

        // GET api/Account/ExternalLogin
        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalCookie)]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)] //refresh token support
        [AllowAnonymous]
        [Route("ExternalLogin", Name = "ExternalLogin")]
        public async Task<IHttpActionResult> GetExternalLogin(string provider, string error = null)
        {

            string redirectUri = string.Empty;

            if (error != null)
            {
                return BadRequest(Uri.EscapeDataString(error));
            }

            if (!User.Identity.IsAuthenticated)
            {
                return new ChallengeResult(provider, this);
            }

            var redirectUriValidationResult = ValidateClientAndRedirectUri(this.Request, ref redirectUri);

            if (!string.IsNullOrWhiteSpace(redirectUriValidationResult))
            {
                return BadRequest(redirectUriValidationResult);
            }

            ExternalLoginData externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);

            if (externalLogin == null)
            {
                return InternalServerError();
            }

            if (externalLogin.LoginProvider != provider)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                return new ChallengeResult(provider, this);
            }

            IdentityUser user = await _repo.FindAsync(new UserLoginInfo(externalLogin.LoginProvider, externalLogin.ProviderKey));

            bool hasRegistered = user != null;

            redirectUri = string.Format("{0}#external_access_token={1}&provider={2}&haslocalaccount={3}&external_user_name={4}&external_access_secret_token={5}",
                                            redirectUri,
                                            externalLogin.ExternalAccessToken,
                                            externalLogin.LoginProvider,
                                            hasRegistered.ToString(),
                                            externalLogin.UserName,
                                            externalLogin.ExternalAccessSectretToken);

            return Redirect(redirectUri);

        }

        [AllowAnonymous]
        [HttpGet]
        [Route("ObtainLocalAccessToken")]
        public async Task<IHttpActionResult> ObtainLocalAccessToken(string provider, string externalAccessToken, string externalAccessSecretToken)
        {

            if (string.IsNullOrWhiteSpace(provider) || string.IsNullOrWhiteSpace(externalAccessToken))
            {
                return BadRequest("Provider or external access token is not sent");
            }

            var verifiedAccessToken = await VerifyExternalAccessToken(provider, externalAccessToken, externalAccessSecretToken);
            if (verifiedAccessToken == null)
            {
                return BadRequest("Invalid Provider or External Access Token");
            }

            IdentityUser user = await _repo.FindAsync(new UserLoginInfo(provider, verifiedAccessToken.user_id));

            bool hasRegistered = user != null;

            if (!hasRegistered)
            {
                return BadRequest("External user is not registered");
            }

            //generate access token response
            var accessTokenResponse = GenerateLocalAccessTokenResponse(user.UserName, provider, verifiedAccessToken.token ?? externalAccessToken, externalAccessSecretToken);

            return Ok(accessTokenResponse);

        }

        //Note this will most likely not be used.
        // POST api/Account/Register
        [AllowAnonymous]
        [Route("Register")]
        public async Task<IHttpActionResult> Register(UserModel userModel)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await _repo.RegisterUser(userModel);

            IHttpActionResult errorResult = GetErrorResult(result);

            if (errorResult != null)
            {
                return errorResult;
            }

            return Ok();
        }

        // POST api/Account/RegisterExternal
        //[AllowAnonymous]
        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("RegisterExternal")]
        public async Task<IHttpActionResult> RegisterExternal(RegisterExternalBindingModel model)
        {

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var state = Request.GetOwinContext();

            var verifiedAccessToken = await VerifyExternalAccessToken(model.Provider, model.ExternalAccessToken, model.ExternalAccessSecretToken);
            if (verifiedAccessToken == null)
            {
                return BadRequest("Invalid Provider or External Access Token");
            }

            IdentityUser user = await _repo.FindAsync(new UserLoginInfo(model.Provider, verifiedAccessToken.user_id));

            bool hasRegistered = user != null;

            if (hasRegistered)
            {
                return BadRequest("External user is already registered");
            }

            user = new IdentityUser() { UserName = model.UserName };

            IdentityResult result = await _repo.CreateAsync(user);
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            var info = new ExternalLoginInfo()
            {
                DefaultUserName = model.UserName,
                Login = new UserLoginInfo(model.Provider, verifiedAccessToken.user_id)
            };

            result = await _repo.AddLoginAsync(user.Id, info.Login);
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            //generate access token response
            var accessTokenResponse = GenerateLocalAccessTokenResponse(model.UserName, model.Provider, model.ExternalAccessToken, model.ExternalAccessSecretToken);

            return Ok(accessTokenResponse);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _repo.Dispose();
            }

            base.Dispose(disposing);
        }

        private IHttpActionResult GetErrorResult(IdentityResult result)
        {
            if (result == null)
            {
                return InternalServerError();
            }

            if (!result.Succeeded)
            {
                if (result.Errors != null)
                {
                    foreach (string error in result.Errors)
                    {
                        ModelState.AddModelError("", error);
                    }
                }

                if (ModelState.IsValid)
                {
                    // No ModelState errors are available to send, so just return an empty BadRequest.
                    return BadRequest();
                }

                return BadRequest(ModelState);
            }

            return null;
        }

        private string ValidateClientAndRedirectUri(HttpRequestMessage request, ref string redirectUriOutput)
        {

            Uri redirectUri;

            var redirectUriString = GetQueryString(Request, "redirect_uri");

            if (string.IsNullOrWhiteSpace(redirectUriString))
            {
                return "redirect_uri is required";
            }

            bool validUri = Uri.TryCreate(redirectUriString, UriKind.Absolute, out redirectUri);

            if (!validUri)
            {
                return "redirect_uri is invalid";
            }

            redirectUriOutput = redirectUri.AbsoluteUri;

            return string.Empty;

        }

        private string GetQueryString(HttpRequestMessage request, string key)
        {
            var queryStrings = request.GetQueryNameValuePairs();

            if (queryStrings == null) return null;

            var match = queryStrings.FirstOrDefault(keyValue => string.Compare(keyValue.Key, key, true) == 0);

            if (string.IsNullOrEmpty(match.Value)) return null;

            return match.Value;
        }

        private async Task<ParsedExternalAccessToken> VerifyExternalAccessToken(string provider, string accessToken, string accessSectret)
        {
            if (provider.Equals("Facebook", StringComparison.OrdinalIgnoreCase))
            {
                return await VerifyFacebookAccessToken(provider, accessToken);
            }
            else if (provider.Equals("Twitter", StringComparison.OrdinalIgnoreCase))
            {
                return await VerifyTwitterAccessToken(provider, accessToken, accessSectret);
            }
            else
            {
                return null;
            }
        }

        private async Task<ParsedExternalAccessToken> VerifyTwitterAccessToken(string provider, string accessToken, string userSecret)
        {
            var verify = new TwitterAuthenticationHandler();
            ParsedExternalAccessToken result = await verify.ObtainCredentialInformationAsync(ConfigurationManager.AppSettings["twitterapp_appid"], ConfigurationManager.AppSettings["twitterapp_appsecret"], accessToken, userSecret);

            return result;
        }

        private static async Task<ParsedExternalAccessToken> VerifyFacebookAccessToken(string provider, string accessToken)
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

        private static List<KeyValuePair<string, string>> ParseIntoKeyValues(string queryString)
        {
            var retVal = new List<KeyValuePair<string, string>>();

            var keys = queryString.Split(new[] { '&' });

            foreach (var key in keys)
            {
                var kv = key.Split(new[] { '=' });
                if (kv.Length == 2)
                {
                    retVal.Add(new KeyValuePair<string, string>(kv[0], kv[1]));
                }
            }

            return retVal;
        }

        private static async Task<string> EnsureFacebookAppToken()
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

        private static async Task<HttpResult> MakeHttpCallWithRetry(string endPoint)
        {
            int counter = 0;
            while (true)
            {
                try
                {
                    counter++;
                    var client = new HttpClient();
                    var uri = new Uri(endPoint);
                    var response = await client.GetAsync(uri);
                    var result = await response.Content.ReadAsStringAsync();
                    return new HttpResult()
                    {
                        Message = response,
                        Response = result
                    };
                }
                catch (Exception)
                {
                    //TODO log
                    if (counter >= 5)
                    {
                        return null;
                    }
                }
            }
        }

        private JObject GenerateLocalAccessTokenResponse(string userName, string provider, string externalAccessToken, string exteralAccessSecretToken)
        {

            var tokenExpiration = TimeSpan.FromDays(1);

            ClaimsIdentity identity = new ClaimsIdentity(OAuthDefaults.AuthenticationType);

            identity.AddClaim(new Claim(ClaimTypes.Name, userName));
            identity.AddClaim(new Claim("role", "user"));
            identity.AddClaim(new Claim("provider", provider));
            identity.AddClaim(new Claim("externalToken", externalAccessToken));
            identity.AddClaim(new Claim("externalSecretToken", exteralAccessSecretToken));

            var props = new AuthenticationProperties()
            {
                IssuedUtc = DateTime.UtcNow,
                ExpiresUtc = DateTime.UtcNow.Add(tokenExpiration),
            };

            var ticket = new AuthenticationTicket(identity, props);

            var accessToken = Startup.OAuthBearerOptions.AccessTokenFormat.Protect(ticket);

            JObject tokenResponse = new JObject(
                                        new JProperty("userName", userName),
                                        new JProperty("access_token", accessToken),
                                        new JProperty("token_type", "bearer"),
                                        new JProperty("expires_in", tokenExpiration.TotalSeconds.ToString()),
                                        new JProperty(".issued", ticket.Properties.IssuedUtc.ToString()),
                                        new JProperty(".expires", ticket.Properties.ExpiresUtc.ToString())
        );

            return tokenResponse;
        }

        private class HttpResult
        {
            public HttpResponseMessage Message { get; set; }
            public string Response { get; set; }
        }

    }
}
