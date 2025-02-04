using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SpfAnalyzer
{
    public class DkimPublicKey
    {
        public string? SignatureAlgorithm { get; set; }
        public int KeySize { get; set; }

        public DkimPublicKey()
        {
        }

        public DkimPublicKey(string signatureAlgorithm, int keySize)
        {
            SignatureAlgorithm = signatureAlgorithm;
            KeySize = keySize;
        }

        public static DkimPublicKey Parse(string algo, string encodedValue)
        {
            var retVal = new DkimPublicKey(algo, 0);
            try
            {
                switch (algo.ToLower())
                {
                    case "rsa":
                        {
                            using var rsa = System.Security.Cryptography.RSA.Create();
                            rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(encodedValue), out _);
                            retVal.KeySize = rsa.KeySize;
                            retVal.SignatureAlgorithm = rsa.SignatureAlgorithm;
                            break;
                        }
                    case "ed25519":
                        {
                            var publicKey = Convert.FromBase64String(encodedValue);
                            retVal.KeySize = publicKey.Length * 8;
                            retVal.SignatureAlgorithm = "Ed25519";
                            break;
                        }
                    default:
                        retVal.KeySize = -1;
                        break;
                }
            }
            catch (Exception)
            {
                retVal.KeySize = -2;
            }
            return retVal;
        }

        public override string ToString()
        {
            return $"{SignatureAlgorithm} {KeySize}";
        }
    }
}
