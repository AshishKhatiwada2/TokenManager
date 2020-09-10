using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Xml.Serialization;

namespace testingapp
{
    class RsaPrivateAndPublicKeyGenerator
    {
        private static RSACryptoServiceProvider csp = new RSACryptoServiceProvider(2048);
        private RSAParameters _privateKey;
        private RSAParameters _publicKey;
        public RsaPrivateAndPublicKeyGenerator()
        {
            _privateKey = csp.ExportParameters(true);
            _publicKey = csp.ExportParameters(false);

        }
        public string PublicKeyString()
        {
            var sw = new StringWriter();
            var xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, _publicKey);


            Console.WriteLine("------public key --------------------------------------------------------------------------------------- public key -------------");
            var x = Encoding.Unicode.GetBytes(sw.ToString());
            Console.WriteLine(x.ToString());
            Console.WriteLine("-----public key ----------------------------------------------------------------------------------------  public key -------------");
            var y = Convert.ToBase64String(x);
            Console.WriteLine(y);
            Console.WriteLine("----public key ----------------------------------------------------------------------------------------- public key -------------");


            return sw.ToString();
        }
        public string PrivateKeyString()
        {
            var sw = new StringWriter();
            var xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, _privateKey);
            Console.WriteLine("---Private key ------------------------------------------------------------------------Private key------------------");
            var x = Encoding.Unicode.GetBytes(sw.ToString());
            Console.WriteLine(x.ToString());
            Console.WriteLine("---Private key ------------------------------------------------------------------------Private key------------------");
            var y = Convert.ToBase64String(x);
            Console.WriteLine(y);
            Console.WriteLine("---Private key ------------------------------------------------------------------------Private key------------------");

            return sw.ToString();
        }
        public string Encrypt(string plainText)
        {
            csp = new RSACryptoServiceProvider();
            csp.ImportParameters(_publicKey);
            var data = Encoding.Unicode.GetBytes(plainText);
            var cypher = csp.Encrypt(data, false);
            return Convert.ToBase64String(cypher); 
        }
        public string Decrypt(string cypherText)
        {
            var dataBytes = Convert.FromBase64String(cypherText);
            csp.ImportParameters(_privateKey);
            var plain = csp.Decrypt(dataBytes, false);
            return Encoding.Unicode.GetString(plain);
        }
        

    }
    public class ExecuteRsa
    {
        public void startEncrytDecrypt()
        {
            string cypher = string.Empty;
            RsaPrivateAndPublicKeyGenerator rs = new RsaPrivateAndPublicKeyGenerator();
            //Console.WriteLine($"PublicKey: \n {rs.PublicKeyString()} \n");
            //Console.WriteLine("Enter your text to encrypt \n");
            //Console.WriteLine("Your public key is = "+ rs.PublicKeyString()+ "\n");
            //Console.WriteLine("Your private key is = " + rs.PrivateKeyString() + "\n");
            //var text = Console.ReadLine();
            //if (text!=string.Empty)
            //{
            //     cypher = rs.Encrypt(text);
            //    Console.WriteLine($"cypher Text: \n {cypher}");

            //}
            //Console.WriteLine("press Enter to Decrypt");
            //Console.ReadLine();
            //var plaintext = rs.Decrypt(cypher);
            //Console.WriteLine("Decrypted Text \n");
            //Console.WriteLine(plaintext);
            //Console.ReadLine();
            rs.PublicKeyString();
            rs.PrivateKeyString();
            Console.Read();
        }
    }
}
