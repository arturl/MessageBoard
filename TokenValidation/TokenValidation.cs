using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
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

        public static SecurityToken ValidateToken(string tokenString, string secret)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.Default.GetBytes(secret));

            var jwt = new JwtSecurityToken(tokenString);

            var tokenValidationParameters = new TokenValidationParameters()
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

            SecurityToken validatedToken;
            var handler = new JwtSecurityTokenHandler();

            handler.ValidateToken(tokenString, tokenValidationParameters, out validatedToken);

            return validatedToken;
        }

        public static string MakeToken(string secret)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.Default.GetBytes(secret));

            var signingCredentials = new SigningCredentials(
                securityKey,
                SecurityAlgorithms.HmacSha512);

            byte[] randomNonce = new Byte[32];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(randomNonce);

            List<Claim> claims = new List<Claim>()
            {
                new Claim("nonce", Convert.ToBase64String(randomNonce))
            };

            var handler = new JwtSecurityTokenHandler();

            var jwtSecurityToken = handler.CreateJwtSecurityToken(
                issuer,
                audience,
                new ClaimsIdentity(claims),
                DateTime.Now,
                DateTime.Now.AddHours(1),
                DateTime.Now,
                signingCredentials);

            string tokenString = handler.WriteToken(jwtSecurityToken);
            return tokenString;
        }
    }
}