using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;

namespace AngularJSAuthentication.API.Providers
{
    public abstract class BaseAuthenticationHandler
    {
        protected async Task<HttpResult> MakeHttpCallWithRetry(string endPoint)
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

        protected List<KeyValuePair<string, string>> ParseIntoKeyValues(string queryString)
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
    }

    public class HttpResult
    {
        public HttpResponseMessage Message { get; set; }
        public string Response { get; set; }
    }
}