using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace testingapp
{
    class FinalCodeToWriteStackOverflow
    {
        const string sec = "bhgjhghjkhgkhgjghkhgjkhkjhgjghkjghkjhkjgytr6u4435234534535yretrttyutytrytetuytuiytyuit76434yyrureytrtyerytreureu1234567890hjhjgfdsaProEMLh5e_qnzdNUrqdHP";
        const string sec1 = "ProEMLh5e_qnzdNU";

        public void encryptToken()
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(sec));
            var securityKey1 = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(sec1));

            var signingCredentials = new SigningCredentials(
                securityKey,
                SecurityAlgorithms.HmacSha512);

            List<Claim> claims = new List<Claim>()
                {
                    new Claim("sub", "test"),
                };

            var ep = new EncryptingCredentials(
                securityKey1,
                SecurityAlgorithms.Aes128KW,
                SecurityAlgorithms.Aes128CbcHmacSha256);

            var handler = new JwtSecurityTokenHandler();

            var jwtSecurityToken = handler.CreateJwtSecurityToken(
                "issuer",
                "Audience",
                new ClaimsIdentity(claims),
                DateTime.Now,
                DateTime.Now.AddHours(1),
                DateTime.Now,
                signingCredentials,
                ep);


            string tokenString = handler.WriteToken(jwtSecurityToken);
            Console.WriteLine("this is the Created Token \n");
            Console.WriteLine(tokenString+ "\n");

            // Id someone tries to view the JWT without validating/decrypting the token,
            // then no claims are retrieved and the token is safe guarded.
            Console.WriteLine("Id someone tries to view the JWT without validating/decrypting the token");
            var jwt = new JwtSecurityToken(tokenString);
            Console.WriteLine(jwt+"\n");
            Console.ReadLine();
            decryptToken(tokenString);
        }
        public void decryptToken(string token)
        {
            
            var securityKey = new SymmetricSecurityKey(Encoding.Default.GetBytes(sec));
            var securityKey1 = new SymmetricSecurityKey(Encoding.Default.GetBytes(sec1));

            // This is the input JWT which we want to validate.
            string tokenString = string.Empty;
            tokenString = token;
            // If we retrieve the token without decrypting the claims, we won't get any claims
            // DO not use this jwt variable
            var jwt = new JwtSecurityToken(tokenString);

            // Verification
                var tokenValidationParameters = new TokenValidationParameters()
                {
                    ValidAudiences = new string[]
                    {
                    "Audience"
                    },
                    ValidIssuers = new string[]
                    {
                    "issuer"
                    },
                    IssuerSigningKey = securityKey,
                    // This is the decryption key
                    TokenDecryptionKey = securityKey1
                };

            SecurityToken validatedToken;
            var handler = new JwtSecurityTokenHandler();
            Console.WriteLine(handler.CanReadToken(token)) ;
            var isCorrect = handler.CanValidateToken;
            Console.WriteLine(isCorrect);
            var x =handler.ValidateToken(tokenString, tokenValidationParameters, out validatedToken);
            Console.WriteLine("\n the value of x is \n");
            Console.WriteLine("Validated Token is \n");
            Console.WriteLine(validatedToken);
            Console.ReadLine();
        }


    }
}
