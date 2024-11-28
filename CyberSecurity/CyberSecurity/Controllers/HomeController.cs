using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CyberSecurity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class HomeController : Controller
    {

        
        
        [HttpPut("testApi")]
        public String testApi([FromBody] string param)
        {
            Console.WriteLine(param);
            return param;
        }

        [HttpPut("cryptWithAESmodeCBC")]
        public IActionResult DecryptAndVerifyMessage([FromBody] string encryptedMessage)
        {
            try
            {
                if (string.IsNullOrEmpty(encryptedMessage))
                    return BadRequest("Le message est vide ou invalide.");

                string key = "1234567890123456";

                byte[] keyBytes = Encoding.UTF8.GetBytes(key);

                byte[] encryptedBytes = Convert.FromBase64String(encryptedMessage);

                byte[] ivBytes = encryptedBytes.Take(16).ToArray();
                byte[] cipherBytes = encryptedBytes.Skip(16).ToArray();

                using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
                {
                    aes.Key = keyBytes;
                    aes.IV = ivBytes;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    ICryptoTransform decryptor = aes.CreateDecryptor();

                    byte[] decryptedBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);

                    string decryptedMessage = Encoding.UTF8.GetString(decryptedBytes);

                    Console.WriteLine($"Message déchiffré : {decryptedMessage}");

                    return Ok(decryptedMessage.Equals("cyber", StringComparison.OrdinalIgnoreCase) ? "true" : "false");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erreur de déchiffrement : {ex.Message}");
                return StatusCode(500, "Erreur interne du serveur");
            }
        }

        [HttpPut("cryptWith3DESmodeEBC")]
        public bool cryptWith3DESmodeEBC()
        {
            // TODO : implémenter le chiffrement avec 3DES en mode EBC
            return true;
        }

        [HttpPut("hashWithSHA1")]
        public bool hashWithSHA1()
        {
            // TODO : implémenter le hachage SHA1
            return true;
        }

        [HttpPut("authWithHMAC")]
        public bool authWithHMAC()
        {
            // TODO : implémenter l'authentification avec HMAC
            return true;
        }

        [HttpPut("signedWithSHAandRSA")]
        public bool signedWithSHAandRSA()
        {
            // TODO : implémenter la signature avec SHA et RSA
            return true;
        }

        [HttpPut("cryptWithRSA")]
        public bool cryptWithRSA()
        {
            // TODO : implémenter le chiffrement avec RSA
            return true;
        }
        [HttpPut("diffieHellman")]
        public double diffieHellman(double  publicKey)
        {
            int random = RandomNumberGenerator.GetInt32(0, 25); // 25 pris arbitrairement
            
            double PublicKeyServer =  Math.Pow(5,random)%23  ;
            Console.WriteLine("clé public serveur : "+ PublicKeyServer );
            
            
            double sharedKey = Math.Pow(publicKey,random) % 23;
            Console.WriteLine("clé partagée : "+ sharedKey );
            
            
            return PublicKeyServer;
        }
    }
}

