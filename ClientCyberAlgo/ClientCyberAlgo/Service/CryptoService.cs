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
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
        }

        public byte[] GenerateSharedSecret()
        {
            // Utilisation de ECDiffieHellman sans dépendance à CNG
            using (ECDiffieHellman ecdh = ECDiffieHellman.Create())
            {
                ecdh.KeySize = 256;
                byte[] publicKey = ecdh.PublicKey.ToByteArray();
                return publicKey;
            }
        }

        public string AesEncryptWithSharedKey(string text, byte[] sharedSecret, out string iv)
        {
            try
            {
                if (string.IsNullOrEmpty(text))
                    throw new ArgumentException("Le texte à chiffrer est vide ou nul.");
                if (sharedSecret == null || sharedSecret.Length == 0)
                    throw new ArgumentException("La clé partagée est vide ou nulle.");

                using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
                {
                    aes.GenerateIV();
                    iv = Convert.ToBase64String(aes.IV);
                    aes.Key = sharedSecret;
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
