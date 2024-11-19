
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
        public string AesEncrypt(string text, string key, out string iv)
        {
            try
            {
                if (string.IsNullOrEmpty(text))
                    throw new ArgumentException("Le texte à chiffrer est vide ou nul.");
                if (string.IsNullOrEmpty(key))
                    throw new ArgumentException("La clé est vide ou nulle.");

                byte[] keyBytes = Encoding.UTF8.GetBytes(key);

                if (keyBytes.Length != 16 && keyBytes.Length != 24 && keyBytes.Length != 32)
                {
                    throw new ArgumentException("La clé doit être de 16, 24 ou 32 octets (128, 192 ou 256 bits).");
                }

                using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
                {
                    aes.GenerateIV();
                    iv = Convert.ToBase64String(aes.IV);
                    aes.Key = keyBytes;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    byte[] textBytes = Encoding.UTF8.GetBytes(text);

                    ICryptoTransform encryptor = aes.CreateEncryptor();
                    byte[] encryptedBytes = encryptor.TransformFinalBlock(textBytes, 0, textBytes.Length);

                    return Convert.ToBase64String(aes.IV.Concat(encryptedBytes).ToArray());
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erreur de chiffrement : {ex.Message}");
                iv = null;
                return null;
            }
        }
    }
}