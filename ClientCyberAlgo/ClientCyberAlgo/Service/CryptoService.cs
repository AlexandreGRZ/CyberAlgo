
using System.Security.Cryptography;
using System.Text;

namespace ClientCyberAlgo.Service
{
    public class CryptoService
    {
        public string Sha1Hash(string text)
        {
            byte[] textBytes = Encoding.UTF8.GetBytes(text);
            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] hashBytes = sha1.ComputeHash(textBytes);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower(); // s'affiche sous le format XX-XX-XX... on retire donc les - 
               
            }
        }
        public string Des3Crypt(string text)
        {
            try
            {
                byte[] key = Encoding.UTF8.GetBytes("123456789012345678901234");
                byte[] textBytes = Encoding.UTF8.GetBytes(text);

                using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
                {
                    tdes.Key = key;
                    tdes.Mode = CipherMode.ECB;
                    tdes.Padding = PaddingMode.PKCS7;

                    ICryptoTransform encryptor = tdes.CreateEncryptor();
                    byte[] encryptedBytes = encryptor.TransformFinalBlock(textBytes, 0, textBytes.Length);

                    return Convert.ToBase64String(encryptedBytes);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erreur de chiffrement : {ex.Message}");
                return null;
            }
        } 
        public string AesEncrypt(string text, string key, string iv)
        {
            try
            {
                byte[] keyBytes = Encoding.UTF8.GetBytes(key);
                byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

                if (keyBytes.Length != 16 && keyBytes.Length != 24 && keyBytes.Length != 32)
                {
                    throw new ArgumentException("La clé doit être de 16, 24 ou 32 octets.");
                }

                byte[] textBytes = Encoding.UTF8.GetBytes(text);

                using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
                {
                    aes.Key = keyBytes;
                    aes.IV = ivBytes;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    ICryptoTransform encryptor = aes.CreateEncryptor();
                    byte[] encryptedBytes = encryptor.TransformFinalBlock(textBytes, 0, textBytes.Length);

                    return Convert.ToBase64String(encryptedBytes);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erreur de chiffrement : {ex.Message}");
                return null;
            }
        }
    }
}