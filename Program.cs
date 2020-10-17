using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AesDecrypt
{
    class AesDecrypt
    {
        public static void Main()
        {
            string data;
            data = File.ReadAllText("./enc.txt");

            var bytes = Convert.FromBase64String(data);

            var key = Convert.FromBase64String("1e5AAsT/Lxh7L5bO54AJ+0aGlkGGuzpeVKHd6KcZo0c=");
            var iv = Convert.FromBase64String("jAUypkBSCh0t96UM8+X2Uw==");

            string decrypted = DecryptStringFromBytes_Aes(bytes, key, iv);

            Console.WriteLine("{0}", decrypted);
        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            string plaintext;

            using (Aes AES = Aes.Create())
            {
                AES.Key = Key;
                AES.IV = IV;
                AES.Mode = CipherMode.CBC;
                AES.Padding = PaddingMode.PKCS7;
                ICryptoTransform decryptor = AES.CreateDecryptor(AES.Key, AES.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
    }
}