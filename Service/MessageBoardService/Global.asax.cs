//----------------------------------------------------------------------------------------------
//    Copyright 2014 Microsoft Corporation
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//----------------------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;

// The following using statements were added for this sample.
using System.Net.Http;
using System.IdentityModel.Tokens;
using System.Threading.Tasks;
using System.Threading;
using System.Net;
using System.IdentityModel.Selectors;
using System.Security.Claims;
using System.Net.Http.Headers;
using System.IdentityModel.Metadata;
using System.ServiceModel.Security;
using System.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Globalization;
using System.Configuration;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Identity.Client;

namespace MessageBoardService
{
    public class WebApiApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            GlobalConfiguration.Configure(WebApiConfig.Register);
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
            GlobalConfiguration.Configuration.MessageHandlers.Add(new TokenValidationHandler());
        }
    }

    internal class TokenValidationHandler : DelegatingHandler
    {
        //
        // The AAD Instance is the instance of Azure, for example public Azure or Azure China.
        // The Tenant is the name of the tenant in which this application is registered.
        // The Authority is the sign-in URL of the tenant.
        // The Audience is the value the service expects to see in tokens that are addressed to it.
        //
        static string aadInstance = "https://login.microsoftonline.com/{0}"; //  ConfigurationManager.AppSettings["ida:AADInstance"];
        static string tenant = "common"; //  "microsoft.onmicrosoft.com"
        //static string tenant = "microsoft.onmicrosoft.com";
        //static string audience = "815a718e-1419-4a51-b90d-28ad6bdecac4"; //ConfigurationManager.AppSettings["ida:Audience"];
        static string audience = "26ad214e-57ce-495b-b9ce-005284263ab6"; //ConfigurationManager.AppSettings["ida:Audience"];
        string authority = String.Format(aadInstance, tenant);

        static string _issuer = string.Empty;
        static List<SecurityToken> _signingTokens = null;
        static DateTime _stsMetadataRetrievalTime = DateTime.MinValue;
        static string scopeClaimType = "http://schemas.microsoft.com/identity/claims/scope";

        class CustomJwtSecurityTokenHandler : JwtSecurityTokenHandler
        {
            protected override JwtSecurityToken ValidateSignature(string token,
                TokenValidationParameters validationParameters)
            {
                try
                {
                    var jwt = base.ValidateSignature(token, validationParameters);
                    return jwt;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"ValidateSignature: ignoring {ex}");
                    return new JwtSecurityToken(token);
                }
            }

            protected override void ValidateAudience(IEnumerable<string> audiences, SecurityToken securityToken, TokenValidationParameters validationParameters)
            {
                try
                {
                    base.ValidateAudience(audiences, securityToken, validationParameters);
                }
                catch(Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"ValidateAudience: ignoring {ex}");
                }
            }

            protected override string ValidateIssuer(string issuer, SecurityToken securityToken, TokenValidationParameters validationParameters)
            {
                try
                {
                    return base.ValidateIssuer(issuer, securityToken, validationParameters);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"ValidateIssuer: ignoring {ex}");
                    return issuer;
                }
            }
        }

        //
        // SendAsync checks that incoming requests have a valid access token, and sets the current user identity using that access token.
        //
        protected async override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Get the jwt bearer token from the authorization header
            string jwtToken = null;
            AuthenticationHeaderValue authHeader = request.Headers.Authorization;
            if (authHeader != null)
            {
                jwtToken = authHeader.Parameter;
            }

            if (jwtToken == null)
            {
                HttpResponseMessage response = BuildResponseErrorMessage(HttpStatusCode.Unauthorized);
                return response;
            }

// This throws with "incorrect assertion or refersh_token"
#if false
            var clientId = "26ad214e-57ce-495b-b9ce-005284263ab6";
            var redirectUri = "https://localhost:44324/";
            // ConfidentialClientApplication myApp = new ConfidentialClientApplication(clientId);
            var appKey = "gdvgMQS72!($sejLMWH308^";

            var myApp = new ConfidentialClientApplication(clientId, redirectUri, new ClientCredential(appKey), null, null);
            var userCount = myApp.Users.Count();

            AuthenticationContext authContext = new AuthenticationContext();

            var ua = new UserAssertion(jwtToken, "urn:ietf:params:oauth:grant-type:jwt-bearer");

            string[] scopes = new string[] { "user.read" };

            var token = await myApp.AcquireTokenOnBehalfOfAsync(scopes, ua);

            var url = "https://graph.microsoft.com/v1.0/me";
            var ss = await GetHttpContentWithToken(url, token.AccessToken);
#endif
            string issuer;
            List<SecurityToken> signingTokens;

            try
            {
                // The issuer and signingTokens are cached for 24 hours. They are updated if any of the conditions in the if condition is true.            
                if (DateTime.UtcNow.Subtract(_stsMetadataRetrievalTime).TotalHours > 24
                    || string.IsNullOrEmpty(_issuer)
                    || _signingTokens == null)
                {
                    // Get tenant information that's used to validate incoming jwt tokens
                    string stsDiscoveryEndpoint = string.Format("{0}/v2.0/.well-known/openid-configuration", authority);
                    var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(stsDiscoveryEndpoint);
                    var config = await configManager.GetConfigurationAsync();
                    _issuer = config.Issuer;
                    _signingTokens = config.SigningTokens.ToList();
                    
                    _stsMetadataRetrievalTime = DateTime.UtcNow;
                }

                issuer = _issuer;
                signingTokens = _signingTokens;
            }
            catch (Exception ex)
            {
                return new HttpResponseMessage(HttpStatusCode.InternalServerError);
            }

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            tokenHandler.Configuration = new SecurityTokenHandlerConfiguration
            {
                CertificateValidator = X509CertificateValidator.None
            };

            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                ValidAudience = audience,
                ValidateAudience = true,

                ValidIssuer = issuer,
                ValidateIssuer = false, // true,

                IssuerSigningTokens = signingTokens,
                RequireSignedTokens = true,
            };

            try
            {
                // Validate token.
                SecurityToken validatedToken = new JwtSecurityToken();
                SecurityToken parsedToken = new JwtSecurityToken(jwtToken);

                // The following fails with: "IDX10500: Signature validation failed. Unable to resolve SecurityKeyIdentifier"
                ClaimsPrincipal claimsPrincipal = tokenHandler.ValidateToken(jwtToken, validationParameters, out validatedToken);

                // Set the ClaimsPrincipal on the current thread.
                Thread.CurrentPrincipal = claimsPrincipal;

                // The ValidateToken method above will return a ClaimsPrincipal.Get the user ID from the NameIdentifier claim
                // (The sub claim from the JWT will be translated to the NameIdentifier claim)
                var user = claimsPrincipal.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value;

                // Set the ClaimsPrincipal on HttpContext.Current if the app is running in web hosted environment.
                if (HttpContext.Current != null)
                {
                    HttpContext.Current.User = claimsPrincipal;
                }

                // If the token is scoped, verify that required permission is set in the scope claim.
                if (ClaimsPrincipal.Current.FindFirst(scopeClaimType) != null && !ClaimsPrincipal.Current.FindFirst(scopeClaimType).Value.Contains("access_as_user"))
                {
                    HttpResponseMessage response = BuildResponseErrorMessage(HttpStatusCode.Forbidden);
                    return response;
                }

                return await base.SendAsync(request, cancellationToken);
            }
            catch (SecurityTokenValidationException ex)
            {
                HttpResponseMessage response = BuildResponseErrorMessage(HttpStatusCode.Unauthorized);
                return response;
            }
            catch (Exception ex)
            {
                return new HttpResponseMessage(HttpStatusCode.InternalServerError);
            }
        }

        private HttpResponseMessage BuildResponseErrorMessage(HttpStatusCode statusCode)
        {
            HttpResponseMessage response = new HttpResponseMessage(statusCode);

            //
            // The Scheme should be "Bearer", authorization_uri should point to the tenant url and resource_id should point to the audience.
            //
            AuthenticationHeaderValue authenticateHeader = new AuthenticationHeaderValue("Bearer", "authorization_uri=\"" + authority + "\"" + "," + "resource_id=" + audience);

            response.Headers.WwwAuthenticate.Add(authenticateHeader);

            return response;
        }
    }
}
