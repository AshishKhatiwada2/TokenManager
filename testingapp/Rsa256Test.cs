using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace testingapp
{
    class Rsa256Test
    {
        public string _PrivateKey { get; set; }
        public string _PublicKey { get; set; }
        public UnicodeEncoding _encoder { get; set; }
        public Rsa256Test()
        {
            _encoder = new UnicodeEncoding();

        }
        public Rsa256Test(string pvtKey, string pblKey)
        {
            _PrivateKey = pvtKey;
            _PublicKey = pblKey;
            _encoder = new UnicodeEncoding();
        }
        
    }
}
