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
        const string privateKey = @"PAA/AHgAbQBsACAAdgBlAHIAcwBpAG8AbgA9ACIAMQAuADAAIgAgAGUAbgBjAG8AZABpAG4AZwA9ACIAdQB0AGYALQAxADYAIgA/AD4ADQAKADwAUgBTAEEAUABhAHIAYQBtAGUAdABlAHIAcwAgAHgAbQBsAG4AcwA6AHgAcwBpAD0AIgBoAHQAdABwADoALwAvAHcAdwB3AC4AdwAzAC4AbwByAGcALwAyADAAMAAxAC8AWABNAEwAUwBjAGgAZQBtAGEALQBpAG4AcwB0AGEAbgBjAGUAIgAgAHgAbQBsAG4AcwA6AHgAcwBkAD0AIgBoAHQAdABwADoALwAvAHcAdwB3AC4AdwAzAC4AbwByAGcALwAyADAAMAAxAC8AWABNAEwAUwBjAGgAZQBtAGEAIgA+AA0ACgAgACAAPABFAHgAcABvAG4AZQBuAHQAPgBBAFEAQQBCADwALwBFAHgAcABvAG4AZQBuAHQAPgANAAoAIAAgADwATQBvAGQAdQBsAHUAcwA+ADcASgBxAEYAOABxAEIAWABzAE8AagBBAHgAbQBwAFcAWQB6AEMASgBIAHAAbQBlADMAWgBZAFMAaQBtAGgAQgBZAGoAWAB1AGwAbwBqAFMAWQBFAGIAVAAxAEcAYwBFADUAWQBEAGkAeQBaAG8AQwA0ADMAYwBLAGoAcgB2AEUAeABrAHoANwBRAGkAQgA4AFcAQQB2ADcAYQBaAHoAZgBmAEIAeAB4AFcAdABWAEUASQAvAHoAaQB3ADMARwBsAE0AZAByAG0AOAA2AC8AcgAzADkAMABUAGIATQBPAGgAMwBkAHUARAAvAEcALwBOAEgAcwBqACsASAAxAG4ASwB6ADMAYwBrAFkAbQBJAC8ASgBBAE8AdgB5AGUASQB3AHgAOAA4AG0AOQBUAEsAaQA2AE4AMQBCAEoANQBuAG0ATABUAEkAbABWAFEAZgBIAFQAdgBBAEoAMwBUAHcAaABBAE8AMgB3AGQATgAwAFcALwBTAGwAMgA4AHYAawBRAFMAYQBVAC8AOABiAG8ATQA5AFkAZwBuAFgAQQAzAGIAcwBmAFoAegBoAGUAYgBIAGYAbAA2AFgAYQBhADcAeABOACsAZQA0AG8ASABxADEAdwB2AE4ASgBUAGUAWABBAFIASABaADIAcgBTAEoAMQBaAEEAUQBHAG0AcABLAEwAVwBYAGEAWABuAEUAQgBIAFgAZwBZAFUAcwBLAFQAZABtAGUAYwBRAHgAUQBKAFUATABSAGMATQBIAEYAbAA4ADAAcwBkAFgAbQBNAEkAeQB3AHgANwBEAHUAMwBOAEoANQAzAE0AOQBFAEoANwBGAHgARgBPAGUALwBpAFEAMgBQAEIAZwBYAEgAMABGAFIAQgBEAHgAUQArADgARQBmAEwAUABpAGMARgBRAD0APQA8AC8ATQBvAGQAdQBsAHUAcwA+AA0ACgAgACAAPABQAD4AKwBxAEUAaABPAEQAeABmAEsAegBMAEgAZwBVADkASQBoAEgAZwA2AFkAagBCAGMAdgBwAFcASwBGAG4AbABnAGEANQBZADEAagBLAEEAMAArADgAUQBWADgAWgByADcAWgBlAHYAaABMAEIAdAAzAHQASgBLAGUAZwArAGcATgB4AGIAUwBCAHEAQQB5AHIAKwA5ADUAdwB3AE0AcQBNAGoAdQBvAHgANgBSAGkAVgBGAFMANABmAEwANwAzAGgALwBHAEoAcQB6AFgASABpAFkAcgBQAEQAOQBkAHUANwBPADAASQBWAFUAcABCAEIASgBrAC8ASgAvAGEAYwAwADYAeQBlAGQAMQA2AEQAWgBSAE4AdABFAGgATwBJAFYAVAAzAFQAZgAzAGQATwBSAEwAOABDAGYAVQB3AE8ANQBlAHQAQgB3AFAANgBQAHkAagA2ADgAPQA8AC8AUAA+AA0ACgAgACAAPABRAD4AOABhAHgAegAyAEkAYQBzAGgAZQBTAFEAQQBwADYAOABPAFUASwAxAHMAOQB0AGYAaAAvAHoAdwBWAFEATwBwAEEAMgBWAFEAawBFAGkAWQA0AE4AdwBnADkAOQAvAFUAVAA1AFgARwB1ADMATQB1AEUATgBlAFIAVgBLAE4AUgBDAFYAZQBVAE0AegBPAEcAMwBlAFIANwBMAHkANQBBAFEATABxAEkAbAAzADEAcQBGAEYAbAB6AGoANABsADQARQB1AEsASAB0AGQAbwBXADMAdgA3AFUAUgBHAHMAbwBkADQATQA2AGwAeQArAC8AWABzAHgAaQBjADAAdAAxAFUAOQBnADcAawBjAHQAcAB2AHIAeQArAHIARABuAEQARgBHADEALwBnADcAYgBqAFYAagBMAEoAbgBjADgATgB6AE0AMgAzAHIASgBZADEAWABYAHMAPQA8AC8AUQA+AA0ACgAgACAAPABEAFAAPgBEAGYAaABQAFIAcgBnAHUAdwBkAFMAcAB4AEMANQBzAEoAMQA0AGcATwB2AHIAaABJAEkAcAByAFUAUQBkAGcAOQBYADUAQQA2ADkANgArAE4AVQA1AGYAdgBzAEQAWgB4AEgAdQBhAGEASAAvADcAYwB5AGcAOQBCADcATQAyAG0AVQArAFAAYgBwAE8ATwBQAHAATABPAGoAQwBCACsASgB6AFUAcwBwAFEAYQBHAHcATgBCADYAVQBvAG4AdAAvADgAaABvAGwAWgAwAEUAZABtAFgANAB4AFUAcQBEAEwARABGAHAAeQBOAGwAYgBtAEUAdwBZAFEAVABoAEIAdgBkADMATwBjAFkAZAA0AHQATgByAFgALwBlAFEAdwBOAGUAYQBZADEAOQArAEUARgB6AHAAUQBaAHkAcwBzACsAbwBpAEYAeQBUAFoAVgBQAGUAYwA9ADwALwBEAFAAPgANAAoAIAAgADwARABRAD4ASwA0AEMAawBkAGMAUwBBAFIANwBYAEYANgBvAEwAUwBWAE8AaABhAE4AdAA3ADEAUwBsAEIAUQBuAHEAMABDAC8AbgBaADkAVQB3AHUATwBZAFcATwBlAGwANQAvADEANABzAEcATwBQAFcAMwBWAFMALwBqAFIAMAAwADkAMgBwAGQAegBhADgANABDAEIAOQBXADEATQBjADAAaQA3AEQAaQB2AEYAcgBLAGQASgBzAGgASQBNAEMARABsAHgAbwBNAHkAZwBLAHkANwB2ADAAUQBKAEUAQwBYAEQAVQBuAHYAYgBEAFYARABXAG4ARwBCAFIAbwBZAEcASwBqADQAdwB6AFkAWgBEADAAZQBjAHQAUQBjADYAbgBtAFgAVQBSAFUASQAwAEIAZgBhAHcAawBoAHcASABIAFUASwBBAGUAVABCAC8ARgBJAHAAbAB3AE0APQA8AC8ARABRAD4ADQAKACAAIAA8AEkAbgB2AGUAcgBzAGUAUQA+AGIAMgBoAEcAZQBtAEgAMABoADUAVABoAHkAbABhAFMAeQB4AHMARQAxAFoAdQBtAFQAawB0ADQASAA2ADMAUwBXAFAAVQBRAEYAeQB6AFIANwB6AGMAOABlAHkAdABiAEQAUQB4AGEAOQA5AFMAVABsAGYAWgBSAFcAYwB2AGEAZwAvADUANwBrAEwAYgBGAG8AaABhADEAZwBLAFMATQBlAG8AMAB0AGIAdQBYAEsAYwA3ACsAZQAvADUAYwBiAG0AUAA3AFMAVgBnAC8AUgBnADgAZAA2AGkAdgBZACsAKwBCADgAcgBGAEgAcwBtAEQAcwBIAHAAVgBHAEgAMABhADUARABEAGoAbQBjAEoASgBnAFQARwAzADUAcgA0AHIAZAAxAEsAMgAwAGYAcQBGADYAOAAvAHcAZAAwAHcARgBpAEoAOQBIAHUAcQArAEwANQBrAD0APAAvAEkAbgB2AGUAcgBzAGUAUQA+AA0ACgAgACAAPABEAD4AYQBGAHEASwA0ADQAVQBXAHkAQgA4AFEARAB6AE0ATgBZAFAAZwBpAE0AZwAzAGQAUgBLAHcAUgBCADEAeQBPAEkAZQB2AFoAagBDAGwAUwBhAEUAWQAwADMAWQBTAEcAWQAxAGIAaQBMADcAcQB1AHQAWABaAG0AZwBLAGUATwBWAFUAdgBVAHMAYwBpADAATAB2ADAAeAA2AE4AWABZAHQAOQB1AHYAbgB6AGwAYQBzAFcAaQB5ADkAegBLAGoAZwBvAGEAaQB3AEMANABDAEkAWgAxAFgARwBPAHgANwA4AHUAYwBEAG8AbwA0AEkAOABTAEEAQwAvAFAANwBVAGQAWQBaADkAMQBLAHEAeQBZAEkAYwBEAHYARQAzADMANQA5AGkAVQB2AFMAYQBWAE4AWgBHAEkAVQBCAGcAUAByAGoAVgBrAHcAOABrAEgAZgBlAGUARgB3AEQAcwBWADcAYwBWAEUAcABSAEgAcAAxADQAOABCADUAaABZAEgAawBOAEMAMQBVACsANAB6AG8ASABwADcAaABZACsANQBkAE8AMQBqAEMASABEADEAdwBhAG4AKwBOAHkARQBMAGcATQB4AG0AbwBiAGEASgBOAFIAOQBXAGcATABwAFoAcgB2AFQASABPADQASABLAGYASQB4AEEAdwBGAE8ARwBBADgAbwBrAEUAaABpAHIAWQBoAHkAQwAwADQAbwA1AFQAQQArAHIAKwBkAG8AMABEAEIAVAB2AHYAWABTAHEAbQBtAGgANABvADUAeABGAGYARgBRADMAeQBxAHAARwBtAE8ANgBmAEcAbgBPADgATQBFAGMAUgB2AGUAQwBsAFUAcQBmAHEAdQBtAFQAWABvAEYAaQBYAFIAZQBIAHcAMQA2AGwAMAB6AFEAPQA9ADwALwBEAD4ADQAKADwALwBSAFMAQQBQAGEAcgBhAG0AZQB0AGUAcgBzAD4A";
        const string publicKey = @"PAA/AHgAbQBsACAAdgBlAHIAcwBpAG8AbgA9ACIAMQAuADAAIgAgAGUAbgBjAG8AZABpAG4AZwA9ACIAdQB0AGYALQAxADYAIgA/AD4ADQAKADwAUgBTAEEAUABhAHIAYQBtAGUAdABlAHIAcwAgAHgAbQBsAG4AcwA6AHgAcwBpAD0AIgBoAHQAdABwADoALwAvAHcAdwB3AC4AdwAzAC4AbwByAGcALwAyADAAMAAxAC8AWABNAEwAUwBjAGgAZQBtAGEALQBpAG4AcwB0AGEAbgBjAGUAIgAgAHgAbQBsAG4AcwA6AHgAcwBkAD0AIgBoAHQAdABwADoALwAvAHcAdwB3AC4AdwAzAC4AbwByAGcALwAyADAAMAAxAC8AWABNAEwAUwBjAGgAZQBtAGEAIgA+AA0ACgAgACAAPABFAHgAcABvAG4AZQBuAHQAPgBBAFEAQQBCADwALwBFAHgAcABvAG4AZQBuAHQAPgANAAoAIAAgADwATQBvAGQAdQBsAHUAcwA+ADcASgBxAEYAOABxAEIAWABzAE8AagBBAHgAbQBwAFcAWQB6AEMASgBIAHAAbQBlADMAWgBZAFMAaQBtAGgAQgBZAGoAWAB1AGwAbwBqAFMAWQBFAGIAVAAxAEcAYwBFADUAWQBEAGkAeQBaAG8AQwA0ADMAYwBLAGoAcgB2AEUAeABrAHoANwBRAGkAQgA4AFcAQQB2ADcAYQBaAHoAZgBmAEIAeAB4AFcAdABWAEUASQAvAHoAaQB3ADMARwBsAE0AZAByAG0AOAA2AC8AcgAzADkAMABUAGIATQBPAGgAMwBkAHUARAAvAEcALwBOAEgAcwBqACsASAAxAG4ASwB6ADMAYwBrAFkAbQBJAC8ASgBBAE8AdgB5AGUASQB3AHgAOAA4AG0AOQBUAEsAaQA2AE4AMQBCAEoANQBuAG0ATABUAEkAbABWAFEAZgBIAFQAdgBBAEoAMwBUAHcAaABBAE8AMgB3AGQATgAwAFcALwBTAGwAMgA4AHYAawBRAFMAYQBVAC8AOABiAG8ATQA5AFkAZwBuAFgAQQAzAGIAcwBmAFoAegBoAGUAYgBIAGYAbAA2AFgAYQBhADcAeABOACsAZQA0AG8ASABxADEAdwB2AE4ASgBUAGUAWABBAFIASABaADIAcgBTAEoAMQBaAEEAUQBHAG0AcABLAEwAVwBYAGEAWABuAEUAQgBIAFgAZwBZAFUAcwBLAFQAZABtAGUAYwBRAHgAUQBKAFUATABSAGMATQBIAEYAbAA4ADAAcwBkAFgAbQBNAEkAeQB3AHgANwBEAHUAMwBOAEoANQAzAE0AOQBFAEoANwBGAHgARgBPAGUALwBpAFEAMgBQAEIAZwBYAEgAMABGAFIAQgBEAHgAUQArADgARQBmAEwAUABpAGMARgBRAD0APQA8AC8ATQBvAGQAdQBsAHUAcwA+AA0ACgA8AC8AUgBTAEEAUABhAHIAYQBtAGUAdABlAHIAcwA+AA==";

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
        public void NewMoreSecureMethodEncrypt()
        {
            List<Claim> claims = new List<Claim>()
                {
                    new Claim("sub", "test"),
                };
            var scKey = Encoding.UTF8.GetBytes(privateKey);
            var ecKeyTemp = Encoding.UTF8.GetBytes(publicKey);

            // Note that the ecKey should have 256 / 8 length:
            byte[] ecKey = new byte[256 / 8];
            Array.Copy(ecKeyTemp, ecKey, 256 / 8);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(
                        scKey),
                        SecurityAlgorithms.HmacSha512),
                EncryptingCredentials = new EncryptingCredentials(
                    new SymmetricSecurityKey(
                        ecKey),
                        SecurityAlgorithms.Aes256KW,
                        SecurityAlgorithms.Aes256CbcHmacSha512),
                Issuer = "My Jwt Issuer",
                Audience = "My Jwt Audience",
                IssuedAt = DateTime.UtcNow,
                Expires = DateTime.Now.AddDays(7),
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);
            var jwt = tokenHandler.WriteToken(token);
            Console.WriteLine("Encrypted token \n"+jwt);
            Console.WriteLine("Press Enter to decrypt token");
            Console.ReadLine();
            NewSecureMethodDecrypt(jwt);
        }
        public void NewSecureMethodDecrypt(string token)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.Default.GetBytes(privateKey));
            var securityKey1 = new SymmetricSecurityKey(Encoding.Default.GetBytes(publicKey));

            // This is the input JWT which we want to validate.
            string tokenString = string.Empty;
            tokenString = token;
            // If we retrieve the token without decrypting the claims, we won't get any claims
            // DO not use this jwt variable
            var jwt = new JwtSecurityToken(tokenString);
            var ecKeyTemp = Encoding.UTF8.GetBytes(publicKey);

            // Note that the ecKey should have 256 / 8 length:
            byte[] ecKey = new byte[256 / 8];
            Array.Copy(ecKeyTemp, ecKey, 256 / 8);
            securityKey1 = new SymmetricSecurityKey(ecKey);
            // Verification
            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudiences = new string[]
                   {
                    "My Jwt Audience"
                   },
                ValidIssuers = new string[]
                   {
                    "My Jwt Issuer"
                   },
                IssuerSigningKey = securityKey,
                // This is the decryption key
                TokenDecryptionKey = securityKey1
            };
            Console.WriteLine("Decrypted token \n");

            SecurityToken validatedToken;
            var handler = new JwtSecurityTokenHandler();
            Console.WriteLine(handler.CanReadToken(token));
            var isCorrect = handler.CanValidateToken;
            Console.WriteLine(isCorrect);
            var x = handler.ValidateToken(tokenString, tokenValidationParameters, out validatedToken);
            Console.WriteLine("\n the value of x is \n");
            Console.WriteLine("Validated Token is \n");
            Console.WriteLine(validatedToken);
            Console.ReadLine();



            
        }

    }
}
