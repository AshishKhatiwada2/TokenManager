﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace testingapp
{
    class JwtTokenCreator
    {
        public JwtTokenCreator()
        {
            
        }
        public void writeToken(string pvtkey = "this is private key to from which token is created")
        {
            JwtTokenCreator jwtTokenCreator = new JwtTokenCreator();
            JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();
            string payload = "user= ashish, password=ashish123";
            string privateKey = @"PAA/AHgAbQBsACAAdgBlAHIAcwBpAG8AbgA9ACIAMQAuADAAIgAgAGUAbgBjAG8AZABpAG4AZwA9ACIAdQB0AGYALQAxADYAIgA/AD4ADQAKADwAUgBTAEEAUABhAHIAYQBtAGUAdABlAHIAcwAgAHgAbQBsAG4AcwA6AHgAcwBpAD0AIgBoAHQAdABwADoALwAvAHcAdwB3AC4AdwAzAC4AbwByAGcALwAyADAAMAAxAC8AWABNAEwAUwBjAGgAZQBtAGEALQBpAG4AcwB0AGEAbgBjAGUAIgAgAHgAbQBsAG4AcwA6AHgAcwBkAD0AIgBoAHQAdABwADoALwAvAHcAdwB3AC4AdwAzAC4AbwByAGcALwAyADAAMAAxAC8AWABNAEwAUwBjAGgAZQBtAGEAIgA+AA0ACgAgACAAPABFAHgAcABvAG4AZQBuAHQAPgBBAFEAQQBCADwALwBFAHgAcABvAG4AZQBuAHQAPgANAAoAIAAgADwATQBvAGQAdQBsAHUAcwA+ADcASgBxAEYAOABxAEIAWABzAE8AagBBAHgAbQBwAFcAWQB6AEMASgBIAHAAbQBlADMAWgBZAFMAaQBtAGgAQgBZAGoAWAB1AGwAbwBqAFMAWQBFAGIAVAAxAEcAYwBFADUAWQBEAGkAeQBaAG8AQwA0ADMAYwBLAGoAcgB2AEUAeABrAHoANwBRAGkAQgA4AFcAQQB2ADcAYQBaAHoAZgBmAEIAeAB4AFcAdABWAEUASQAvAHoAaQB3ADMARwBsAE0AZAByAG0AOAA2AC8AcgAzADkAMABUAGIATQBPAGgAMwBkAHUARAAvAEcALwBOAEgAcwBqACsASAAxAG4ASwB6ADMAYwBrAFkAbQBJAC8ASgBBAE8AdgB5AGUASQB3AHgAOAA4AG0AOQBUAEsAaQA2AE4AMQBCAEoANQBuAG0ATABUAEkAbABWAFEAZgBIAFQAdgBBAEoAMwBUAHcAaABBAE8AMgB3AGQATgAwAFcALwBTAGwAMgA4AHYAawBRAFMAYQBVAC8AOABiAG8ATQA5AFkAZwBuAFgAQQAzAGIAcwBmAFoAegBoAGUAYgBIAGYAbAA2AFgAYQBhADcAeABOACsAZQA0AG8ASABxADEAdwB2AE4ASgBUAGUAWABBAFIASABaADIAcgBTAEoAMQBaAEEAUQBHAG0AcABLAEwAVwBYAGEAWABuAEUAQgBIAFgAZwBZAFUAcwBLAFQAZABtAGUAYwBRAHgAUQBKAFUATABSAGMATQBIAEYAbAA4ADAAcwBkAFgAbQBNAEkAeQB3AHgANwBEAHUAMwBOAEoANQAzAE0AOQBFAEoANwBGAHgARgBPAGUALwBpAFEAMgBQAEIAZwBYAEgAMABGAFIAQgBEAHgAUQArADgARQBmAEwAUABpAGMARgBRAD0APQA8AC8ATQBvAGQAdQBsAHUAcwA+AA0ACgAgACAAPABQAD4AKwBxAEUAaABPAEQAeABmAEsAegBMAEgAZwBVADkASQBoAEgAZwA2AFkAagBCAGMAdgBwAFcASwBGAG4AbABnAGEANQBZADEAagBLAEEAMAArADgAUQBWADgAWgByADcAWgBlAHYAaABMAEIAdAAzAHQASgBLAGUAZwArAGcATgB4AGIAUwBCAHEAQQB5AHIAKwA5ADUAdwB3AE0AcQBNAGoAdQBvAHgANgBSAGkAVgBGAFMANABmAEwANwAzAGgALwBHAEoAcQB6AFgASABpAFkAcgBQAEQAOQBkAHUANwBPADAASQBWAFUAcABCAEIASgBrAC8ASgAvAGEAYwAwADYAeQBlAGQAMQA2AEQAWgBSAE4AdABFAGgATwBJAFYAVAAzAFQAZgAzAGQATwBSAEwAOABDAGYAVQB3AE8ANQBlAHQAQgB3AFAANgBQAHkAagA2ADgAPQA8AC8AUAA+AA0ACgAgACAAPABRAD4AOABhAHgAegAyAEkAYQBzAGgAZQBTAFEAQQBwADYAOABPAFUASwAxAHMAOQB0AGYAaAAvAHoAdwBWAFEATwBwAEEAMgBWAFEAawBFAGkAWQA0AE4AdwBnADkAOQAvAFUAVAA1AFgARwB1ADMATQB1AEUATgBlAFIAVgBLAE4AUgBDAFYAZQBVAE0AegBPAEcAMwBlAFIANwBMAHkANQBBAFEATABxAEkAbAAzADEAcQBGAEYAbAB6AGoANABsADQARQB1AEsASAB0AGQAbwBXADMAdgA3AFUAUgBHAHMAbwBkADQATQA2AGwAeQArAC8AWABzAHgAaQBjADAAdAAxAFUAOQBnADcAawBjAHQAcAB2AHIAeQArAHIARABuAEQARgBHADEALwBnADcAYgBqAFYAagBMAEoAbgBjADgATgB6AE0AMgAzAHIASgBZADEAWABYAHMAPQA8AC8AUQA+AA0ACgAgACAAPABEAFAAPgBEAGYAaABQAFIAcgBnAHUAdwBkAFMAcAB4AEMANQBzAEoAMQA0AGcATwB2AHIAaABJAEkAcAByAFUAUQBkAGcAOQBYADUAQQA2ADkANgArAE4AVQA1AGYAdgBzAEQAWgB4AEgAdQBhAGEASAAvADcAYwB5AGcAOQBCADcATQAyAG0AVQArAFAAYgBwAE8ATwBQAHAATABPAGoAQwBCACsASgB6AFUAcwBwAFEAYQBHAHcATgBCADYAVQBvAG4AdAAvADgAaABvAGwAWgAwAEUAZABtAFgANAB4AFUAcQBEAEwARABGAHAAeQBOAGwAYgBtAEUAdwBZAFEAVABoAEIAdgBkADMATwBjAFkAZAA0AHQATgByAFgALwBlAFEAdwBOAGUAYQBZADEAOQArAEUARgB6AHAAUQBaAHkAcwBzACsAbwBpAEYAeQBUAFoAVgBQAGUAYwA9ADwALwBEAFAAPgANAAoAIAAgADwARABRAD4ASwA0AEMAawBkAGMAUwBBAFIANwBYAEYANgBvAEwAUwBWAE8AaABhAE4AdAA3ADEAUwBsAEIAUQBuAHEAMABDAC8AbgBaADkAVQB3AHUATwBZAFcATwBlAGwANQAvADEANABzAEcATwBQAFcAMwBWAFMALwBqAFIAMAAwADkAMgBwAGQAegBhADgANABDAEIAOQBXADEATQBjADAAaQA3AEQAaQB2AEYAcgBLAGQASgBzAGgASQBNAEMARABsAHgAbwBNAHkAZwBLAHkANwB2ADAAUQBKAEUAQwBYAEQAVQBuAHYAYgBEAFYARABXAG4ARwBCAFIAbwBZAEcASwBqADQAdwB6AFkAWgBEADAAZQBjAHQAUQBjADYAbgBtAFgAVQBSAFUASQAwAEIAZgBhAHcAawBoAHcASABIAFUASwBBAGUAVABCAC8ARgBJAHAAbAB3AE0APQA8AC8ARABRAD4ADQAKACAAIAA8AEkAbgB2AGUAcgBzAGUAUQA+AGIAMgBoAEcAZQBtAEgAMABoADUAVABoAHkAbABhAFMAeQB4AHMARQAxAFoAdQBtAFQAawB0ADQASAA2ADMAUwBXAFAAVQBRAEYAeQB6AFIANwB6AGMAOABlAHkAdABiAEQAUQB4AGEAOQA5AFMAVABsAGYAWgBSAFcAYwB2AGEAZwAvADUANwBrAEwAYgBGAG8AaABhADEAZwBLAFMATQBlAG8AMAB0AGIAdQBYAEsAYwA3ACsAZQAvADUAYwBiAG0AUAA3AFMAVgBnAC8AUgBnADgAZAA2AGkAdgBZACsAKwBCADgAcgBGAEgAcwBtAEQAcwBIAHAAVgBHAEgAMABhADUARABEAGoAbQBjAEoASgBnAFQARwAzADUAcgA0AHIAZAAxAEsAMgAwAGYAcQBGADYAOAAvAHcAZAAwAHcARgBpAEoAOQBIAHUAcQArAEwANQBrAD0APAAvAEkAbgB2AGUAcgBzAGUAUQA+AA0ACgAgACAAPABEAD4AYQBGAHEASwA0ADQAVQBXAHkAQgA4AFEARAB6AE0ATgBZAFAAZwBpAE0AZwAzAGQAUgBLAHcAUgBCADEAeQBPAEkAZQB2AFoAagBDAGwAUwBhAEUAWQAwADMAWQBTAEcAWQAxAGIAaQBMADcAcQB1AHQAWABaAG0AZwBLAGUATwBWAFUAdgBVAHMAYwBpADAATAB2ADAAeAA2AE4AWABZAHQAOQB1AHYAbgB6AGwAYQBzAFcAaQB5ADkAegBLAGoAZwBvAGEAaQB3AEMANABDAEkAWgAxAFgARwBPAHgANwA4AHUAYwBEAG8AbwA0AEkAOABTAEEAQwAvAFAANwBVAGQAWQBaADkAMQBLAHEAeQBZAEkAYwBEAHYARQAzADMANQA5AGkAVQB2AFMAYQBWAE4AWgBHAEkAVQBCAGcAUAByAGoAVgBrAHcAOABrAEgAZgBlAGUARgB3AEQAcwBWADcAYwBWAEUAcABSAEgAcAAxADQAOABCADUAaABZAEgAawBOAEMAMQBVACsANAB6AG8ASABwADcAaABZACsANQBkAE8AMQBqAEMASABEADEAdwBhAG4AKwBOAHkARQBMAGcATQB4AG0AbwBiAGEASgBOAFIAOQBXAGcATABwAFoAcgB2AFQASABPADQASABLAGYASQB4AEEAdwBGAE8ARwBBADgAbwBrAEUAaABpAHIAWQBoAHkAQwAwADQAbwA1AFQAQQArAHIAKwBkAG8AMABEAEIAVAB2AHYAWABTAHEAbQBtAGgANABvADUAeABGAGYARgBRADMAeQBxAHAARwBtAE8ANgBmAEcAbgBPADgATQBFAGMAUgB2AGUAQwBsAFUAcQBmAHEAdQBtAFQAWABvAEYAaQBYAFIAZQBIAHcAMQA2AGwAMAB6AFEAPQA9ADwALwBEAD4ADQAKADwALwBSAFMAQQBQAGEAcgBhAG0AZQB0AGUAcgBzAD4A";
            if (pvtkey!= "this is private key to from which token is created")
            {
                privateKey = pvtkey;
            }
            string publicKey = @"PAA/AHgAbQBsACAAdgBlAHIAcwBpAG8AbgA9ACIAMQAuADAAIgAgAGUAbgBjAG8AZABpAG4AZwA9ACIAdQB0AGYALQAxADYAIgA/AD4ADQAKADwAUgBTAEEAUABhAHIAYQBtAGUAdABlAHIAcwAgAHgAbQBsAG4AcwA6AHgAcwBpAD0AIgBoAHQAdABwADoALwAvAHcAdwB3AC4AdwAzAC4AbwByAGcALwAyADAAMAAxAC8AWABNAEwAUwBjAGgAZQBtAGEALQBpAG4AcwB0AGEAbgBjAGUAIgAgAHgAbQBsAG4AcwA6AHgAcwBkAD0AIgBoAHQAdABwADoALwAvAHcAdwB3AC4AdwAzAC4AbwByAGcALwAyADAAMAAxAC8AWABNAEwAUwBjAGgAZQBtAGEAIgA+AA0ACgAgACAAPABFAHgAcABvAG4AZQBuAHQAPgBBAFEAQQBCADwALwBFAHgAcABvAG4AZQBuAHQAPgANAAoAIAAgADwATQBvAGQAdQBsAHUAcwA+ADcASgBxAEYAOABxAEIAWABzAE8AagBBAHgAbQBwAFcAWQB6AEMASgBIAHAAbQBlADMAWgBZAFMAaQBtAGgAQgBZAGoAWAB1AGwAbwBqAFMAWQBFAGIAVAAxAEcAYwBFADUAWQBEAGkAeQBaAG8AQwA0ADMAYwBLAGoAcgB2AEUAeABrAHoANwBRAGkAQgA4AFcAQQB2ADcAYQBaAHoAZgBmAEIAeAB4AFcAdABWAEUASQAvAHoAaQB3ADMARwBsAE0AZAByAG0AOAA2AC8AcgAzADkAMABUAGIATQBPAGgAMwBkAHUARAAvAEcALwBOAEgAcwBqACsASAAxAG4ASwB6ADMAYwBrAFkAbQBJAC8ASgBBAE8AdgB5AGUASQB3AHgAOAA4AG0AOQBUAEsAaQA2AE4AMQBCAEoANQBuAG0ATABUAEkAbABWAFEAZgBIAFQAdgBBAEoAMwBUAHcAaABBAE8AMgB3AGQATgAwAFcALwBTAGwAMgA4AHYAawBRAFMAYQBVAC8AOABiAG8ATQA5AFkAZwBuAFgAQQAzAGIAcwBmAFoAegBoAGUAYgBIAGYAbAA2AFgAYQBhADcAeABOACsAZQA0AG8ASABxADEAdwB2AE4ASgBUAGUAWABBAFIASABaADIAcgBTAEoAMQBaAEEAUQBHAG0AcABLAEwAVwBYAGEAWABuAEUAQgBIAFgAZwBZAFUAcwBLAFQAZABtAGUAYwBRAHgAUQBKAFUATABSAGMATQBIAEYAbAA4ADAAcwBkAFgAbQBNAEkAeQB3AHgANwBEAHUAMwBOAEoANQAzAE0AOQBFAEoANwBGAHgARgBPAGUALwBpAFEAMgBQAEIAZwBYAEgAMABGAFIAQgBEAHgAUQArADgARQBmAEwAUABpAGMARgBRAD0APQA8AC8ATQBvAGQAdQBsAHUAcwA+AA0ACgA8AC8AUgBTAEEAUABhAHIAYQBtAGUAdABlAHIAcwA+AA==";
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(privateKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new Claim[]
            {
                new Claim("userName","ashish"),
                new Claim("role","admin"),
                new Claim("id","121212")
            };
            var jwtToken = new JwtSecurityToken("xyz", "abc", claims, DateTime.Now, DateTime.Now.AddHours(1), credentials);
            Console.WriteLine(new JwtSecurityTokenHandler().WriteToken(jwtToken));
        }
    }
}
