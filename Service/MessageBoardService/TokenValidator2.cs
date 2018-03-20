
using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;

namespace MessageBoardService
{
    internal static class TokenValidatorHandler2
    {
        static string aadInstance = "https://login.microsoftonline.com/{0}";
        static string tenant = "common"; //  "microsoft.onmicrosoft.com"
        //static string tenant = "microsoft.onmicrosoft.com";
        static string audience = "26ad214e-57ce-495b-b9ce-005284263ab6";
        static string authority = String.Format(aadInstance, tenant);

        static string _issuer = string.Empty;
        static List<SecurityToken> _signingTokens = null;
        static DateTime _stsMetadataRetrievalTime = DateTime.MinValue;
        
        //
        // SendAsync checks that incoming requests have a valid access token, and sets the current user identity using that access token.
        //
        public static async Task<string> ValidateTokenInHttpRequest(HttpRequestMessage request)
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
                throw new UnauthorizedAccessException("Missing token in authorization header");
            }

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
                throw;
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
                return user;
            }
            catch (SecurityTokenValidationException)
            {
                throw; // TODO: log or remove
            }
            catch (Exception)
            {
                throw;
            }
        }
    }
}
