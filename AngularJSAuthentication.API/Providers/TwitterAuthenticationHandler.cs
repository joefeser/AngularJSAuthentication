using AngularJSAuthentication.API.Models;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace AngularJSAuthentication.API.Providers
{

    public class TwitterAuthenticationHandler
    {
        private const string SettingsEndpoint = "https://api.twitter.com/1.1/account/verify_credentials.json";

        private static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        private readonly HttpClient _httpClient = new HttpClient();

        public async Task<ParsedExternalAccessToken> ObtainCredentialInformationAsync(string userToken, string userSecret)
        {
            string consumerKey = ConfigurationManager.AppSettings["twitterapp_appid"];
            string consumerSecret = ConfigurationManager.AppSettings["twitterapp_appsecret"];

            string nonce = Guid.NewGuid().ToString("N");
            SortedDictionary<string, string> sortedDictionary = new SortedDictionary<string, string>
			    {
				    {
					    "oauth_consumer_key",
					    consumerKey
				    },
				    {
					    "oauth_nonce",
					    nonce
				    },
				    {
					    "oauth_signature_method",
					    "HMAC-SHA1"
				    },
				    {
					    "oauth_token",
					    userToken
				    },
				    {
					    "oauth_timestamp",
					    TwitterAuthenticationHandler.GenerateTimeStamp()
				    },
                    {
					    "oauth_version",
					    "1.0"
				    },
				
				    {
					    "include_entities",
					    "false"
				    },
                    {
					    "skip_status",
					    "true"
				    }
			    };
            StringBuilder stringBuilder = new StringBuilder();
            foreach (KeyValuePair<string, string> current in sortedDictionary)
            {
                stringBuilder.AppendFormat("{0}={1}&", Uri.EscapeDataString(current.Key), Uri.EscapeDataString(current.Value));
            }
            stringBuilder.Length--;
            string stringToEscape = stringBuilder.ToString();
            StringBuilder stringBuilder2 = new StringBuilder();
            stringBuilder2.Append(HttpMethod.Get.Method);
            stringBuilder2.Append("&");
            stringBuilder2.Append(Uri.EscapeDataString(SettingsEndpoint));
            stringBuilder2.Append("&");
            stringBuilder2.Append(Uri.EscapeDataString(stringToEscape));
            string signature = TwitterAuthenticationHandler.ComputeSignature(consumerSecret, userSecret, stringBuilder2.ToString());
            sortedDictionary.Add("oauth_signature", signature);
            StringBuilder oauthHeader = new StringBuilder();
            oauthHeader.Append("OAuth ");
            foreach (KeyValuePair<string, string> current2 in sortedDictionary)
            {
                oauthHeader.AppendFormat("{0}=\"{1}\", ", current2.Key, Uri.EscapeDataString(current2.Value));
            }
            oauthHeader.Length -= 2;
            HttpRequestMessage httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, SettingsEndpoint + "?include_entities=false&skip_status=true");
            httpRequestMessage.Headers.Add("Authorization", oauthHeader.ToString());
            HttpResponseMessage httpResponseMessage = await this._httpClient.SendAsync(httpRequestMessage, new CancellationToken());
            if (!httpResponseMessage.IsSuccessStatusCode)
            {
                httpResponseMessage.EnsureSuccessStatusCode();
            }
            string text = await httpResponseMessage.Content.ReadAsStringAsync();

            var response = Newtonsoft.Json.JsonConvert.DeserializeObject<TwitterUserSettings>(text);

            return new ParsedExternalAccessToken
            {
                token = userToken,
                screen_name = response.screen_name,
                app_id = 0.ToString(),
                valid = true,
                user_id = response.id.ToString()
            };
        }

        private static string GenerateTimeStamp()
        {
            return Convert.ToInt64((DateTime.UtcNow - TwitterAuthenticationHandler.Epoch).TotalSeconds).ToString(CultureInfo.InvariantCulture);
        }

        private static string ComputeSignature(string consumerSecret, string tokenSecret, string signatureData)
        {
            string result;
            using (HMACSHA1 hMACSHA = new HMACSHA1())
            {
                hMACSHA.Key = Encoding.ASCII.GetBytes(string.Format(CultureInfo.InvariantCulture, "{0}&{1}", new object[]
				    {
					    Uri.EscapeDataString(consumerSecret),
					    string.IsNullOrEmpty(tokenSecret) ? string.Empty : Uri.EscapeDataString(tokenSecret)
				    }));
                byte[] inArray = hMACSHA.ComputeHash(Encoding.ASCII.GetBytes(signatureData));
                result = Convert.ToBase64String(inArray);
            }
            return result;
        }
    }

}