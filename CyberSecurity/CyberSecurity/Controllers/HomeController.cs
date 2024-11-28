using CyberSecurity.Service;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Security.Cryptography;
using System.Text;

namespace CyberSecurity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class HomeController : Controller
    {
        
        private Crypto_service _cryptoService;

        public HomeController(Crypto_service service )
        {
            _cryptoService = service;
        }
        
        // api de test pour checker si la communication avec l'app passe bien 
        [HttpPut("testApi")]
        public String testApi( [FromBody] String param)
        {
            
            Console.WriteLine(param);
            return param;
        }
        
        [HttpPut("cryptWith3DESmodeEBC")]
        public bool cryptWith3DESmodeEBC()
        {
            //todo :  msg chiffré avec 3DES en mode EBC , les clés sont hardcodé
            return true;
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

        [HttpPut("hashWithSHA1")]
        public bool hashWithSHA1(string message ,string  hash )
        {
            
            string calculatedhash =_cryptoService.Sha1Hash(message);
            Console.WriteLine($"Mot de passe haché : {calculatedhash}");
            Console.WriteLine($"hash reçu : {hash}");
            if (calculatedhash != hash)
            {
                return false;
            }
            
            return true;
        }
          
        [HttpPut("authWithHMAC")]
        public bool authWithHMAC()
        {
            //todo : msg authentifié avec un hmac MD5 la clé peut etre hardcodé 
            return true;
        }
        [HttpPut("signedWithSHAandRSA")]
        public bool signedWithSHAandRSA()
        {
            //todo : msg signé avec sha 1 et RSA , clé peuvent eter hardcodé ou transmise sur le réseaux
            return true;
        }
        [HttpPut("cryptWithRSA")]
        public bool cryptWithRSA()
        {
            // todo : le msg est chiffré a l'aide de RSA , la clé publique provient
            // d'un certificat save dans un keystore
            return true;
        }
             
    }
}