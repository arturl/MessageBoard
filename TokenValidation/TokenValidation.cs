using System;
using System.Collections.Generic;
//using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace TokenValidation
{
    public static class Tokens
    {
        private const string audience = "MB";
        private const string issuer = "Message Board Platform";

        public static void ValidateToken(string tokenString, string secret)
        {
            var securityKey = new System.IdentityModel.Tokens.InMemorySymmetricSecurityKey(Encoding.Default.GetBytes(secret));

            var jwt = new System.IdentityModel.Tokens.JwtSecurityToken(tokenString);

            var tokenValidationParameters = new System.IdentityModel.Tokens.TokenValidationParameters()
            {
                ValidAudiences = new string[]
                {
                    audience
                },
                ValidIssuers = new string[]
                {
                    issuer
                },
                IssuerSigningKey = securityKey
            };

            System.IdentityModel.Tokens.SecurityToken validatedToken;
            var handler = new System.IdentityModel.Tokens.JwtSecurityTokenHandler();

            handler.ValidateToken(tokenString, tokenValidationParameters, out validatedToken);
        }

        public static string MakeToken(string secret, string user)
        {
            var securityKey = new System.IdentityModel.Tokens.InMemorySymmetricSecurityKey(Encoding.Default.GetBytes(secret));

            System.IdentityModel.Tokens.SigningCredentials signingCredentials = 
                new System.IdentityModel.Tokens.SigningCredentials(
                    securityKey,
                    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
                    "http://www.w3.org/2001/04/xmlenc#sha256");

            byte[] randomNonce = new Byte[32];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(randomNonce);

            List<Claim> claims = new List<Claim>()
            {
                new Claim("user", user),
                new Claim("nonce", Convert.ToBase64String(randomNonce)),
            };

            var jwtSecurityToken = new System.IdentityModel.Tokens.JwtSecurityToken(
                issuer,
                audience,
                claims,
                DateTime.Now,
                DateTime.Now.AddHours(1),
                signingCredentials
                );

            var handler = new System.IdentityModel.Tokens.JwtSecurityTokenHandler();

            string tokenString = handler.WriteToken(jwtSecurityToken);
            return tokenString;
        }
    }
}