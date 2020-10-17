using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace RSADecryptor
{
    class Program
    {
        public static void Main()
        {
            string datakey;
            datakey = File.ReadAllText("./key64").Trim();

            string dataiv;
            dataiv = File.ReadAllText("./iv64").Trim();

            StreamReader sr = new StreamReader("./ans");
            PemReader pr = new PemReader(sr);
            AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
            RSAParameters rsap = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)KeyPair.Private);
            
            
            var bytes = Convert.FromBase64String(datakey);
            string decrypted = DecryptStringFromBytes_RSA(bytes, rsap);

            Console.WriteLine("key: {0}", decrypted);

            bytes = Convert.FromBase64String(dataiv);
            decrypted = DecryptStringFromBytes_RSA(bytes, rsap);

            Console.WriteLine("iv: {0}", decrypted);
        }

        static string DecryptStringFromBytes_RSA(byte[] cipherText, RSAParameters rsap)
        {
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");

            string plaintext;
            
            using (var RSA = System.Security.Cryptography.RSA.Create(rsap))
            {
                
                var bytes = RSA.Decrypt(cipherText, RSAEncryptionPadding.Pkcs1);

                plaintext = Convert.ToBase64String(bytes);


            }

            return plaintext;
        }
    }
}
