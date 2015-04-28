using Aminjam.Owin.Security.Instagram;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace AngularJSAuthentication.API.Providers
{
    public class InstagramAuthProvider : IInstagramAuthenticationProvider
    {
        public System.Threading.Tasks.Task Authenticated(InstagramAuthenticatedContext context)
        {
            context.Identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));
            context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id));
            context.Identity.AddClaim(new Claim("urn:instagram:fullName", context.FullName));
            context.Identity.AddClaim(new Claim("urn:instagram:profilePic", context.ProfilePicture));
            context.Identity.AddClaim(new Claim("ExternalAccessToken", context.AccessToken));
            return Task.FromResult<object>(null);
        }

        public System.Threading.Tasks.Task ReturnEndpoint(InstagramReturnEndpointContext context)
        {
            return Task.FromResult(true);
        }
    }
}