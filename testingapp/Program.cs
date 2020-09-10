using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace testingapp
{
    class Program
    {
        static void Main(string[] args)
        {
            //OldMethod();
            //newMethod();
            //VeleMethod();
            bestMethodTillFound();

        }
        private static void bestMethodTillFound()
        {
            FinalCodeToWriteStackOverflow finalCodeToWriteStackOverflow = new FinalCodeToWriteStackOverflow();
            finalCodeToWriteStackOverflow.encryptToken();
            //finalCodeToWriteStackOverflow.NewMoreSecureMethodEncrypt();

        }
        private static void VeleMethod()
        {
            JwtTokenCreator jwtToken = new JwtTokenCreator();
            jwtToken.writeToken();
            Console.Read();

        }
        private static void newMethod()
        {
            ExecuteRsa executeRsa = new ExecuteRsa();
            executeRsa.startEncrytDecrypt();

        }
        private static void OldMethod()
        {
            //Random random = new Random();
            //int randx = random.Next();
            //byte[] randb = new byte[] { byte.Parse(randx.ToString()) };

            //SHA512Managed sha = new SHA512Managed();
            //var result =sha.ComputeHash(randb);
            //var x = sha.Hash;
            //Console.WriteLine(x);


            //Console.WriteLine("this is from the stackoverflow");
            //Console.WriteLine(security());
            //Console.ReadLine();


            // Generate a new random password string
            string myPassword = Password.CreateRandomPassword(10);

            // Debug output
            Console.WriteLine(myPassword);

            // Generate a new random salt
            int mySalt = Password.CreateRandomSalt();
            Console.WriteLine(mySalt);
            // Initialize the Password class with the password and salt
            Password pwd = new Password(myPassword, mySalt);
            Console.WriteLine(pwd);
            // Compute the salted hash
            // NOTE: you store the salt and the salted hash in the datbase
            string strHashedPassword = pwd.ComputeSaltedHash();
            Console.WriteLine(strHashedPassword);
            // Debug output
            Console.WriteLine(strHashedPassword);
            Console.Read();
        }

        public static string security()
        {

            byte[] x;
            var data = Encoding.UTF8.GetBytes("text");
            using (SHA512 shaM = new SHA512Managed())
            {
                byte[] hash = shaM.ComputeHash(data);
                x = hash;
            }

            Console.WriteLine(x);
            return x.ToString();

        }
    }
    public class Password
    {
        public static string CreateRandomPassword(int PasswordLength)
        {
            String _allowedChars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ23456789";
            Byte[] randomBytes = new Byte[PasswordLength];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(randomBytes);
            char[] chars = new char[PasswordLength];
            int allowedCharCount = _allowedChars.Length;

            for (int i = 0; i < PasswordLength; i++)
            {
                chars[i] = _allowedChars[(int)randomBytes[i] % allowedCharCount];
            }

            return new string(chars);
        }
        public static int CreateRandomSalt()
        {
            Byte[] _saltBytes = new Byte[4];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(_saltBytes);

            return ((((int)_saltBytes[0]) << 24) + (((int)_saltBytes[1]) << 16) +
              (((int)_saltBytes[2]) << 8) + ((int)_saltBytes[3]));
        }



        private string _password;
        private int _salt;

        public Password(string strPassword, int nSalt)
        {
            _password = strPassword;
            _salt = nSalt;
        }
        public string ComputeSaltedHash()
        {
            // Create Byte array of password string
            ASCIIEncoding encoder = new ASCIIEncoding();
            Byte[] _secretBytes = encoder.GetBytes(_password);

            // Create a new salt
            Byte[] _saltBytes = new Byte[4];
            _saltBytes[0] = (byte)(_salt >> 24);
            _saltBytes[1] = (byte)(_salt >> 16);
            _saltBytes[2] = (byte)(_salt >> 8);
            _saltBytes[3] = (byte)(_salt);

            // append the two arrays
            Byte[] toHash = new Byte[_secretBytes.Length + _saltBytes.Length];
            Array.Copy(_secretBytes, 0, toHash, 0, _secretBytes.Length);
            Array.Copy(_saltBytes, 0, toHash, _secretBytes.Length, _saltBytes.Length);

            SHA1 sha1 = SHA1.Create();
            Byte[] computedHash = sha1.ComputeHash(toHash);

            return encoder.GetString(computedHash);
        }
    }
}
