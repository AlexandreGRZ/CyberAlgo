
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
        
        public string TripleDESEncrypt(string text, string key)
        {
            try
            {
                if (string.IsNullOrEmpty(text))
                    throw new ArgumentException("Le texte à chiffrer est vide ou nul.");
                if (string.IsNullOrEmpty(key))
                    throw new ArgumentException("La clé est vide ou nulle.");

                byte[] keyBytes = Encoding.UTF8.GetBytes(key);

                if (keyBytes.Length != 24)
                {
                    throw new ArgumentException("La clé doit être de 24 octets (192 bits).");
                }

                using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
                {
                    tdes.Key = keyBytes;
                    tdes.Mode = CipherMode.ECB;
                    tdes.Padding = PaddingMode.PKCS7;

                    byte[] textBytes = Encoding.UTF8.GetBytes(text);

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
    }
}