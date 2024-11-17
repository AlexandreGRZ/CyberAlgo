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
        
        // api de test pour checker si la communication avec l'app passe bien 
        [HttpPut("testApi")]
        public String testApi( [FromBody] String param)
        {
            
            Console.WriteLine(param);
            return param;
        }
        
        [HttpPut("cryptWith3DESmodeEBC")]
        public IActionResult CryptWith3DESmodeEBC([FromBody] string encryptedMessage)
        {
            try
            {
                if (string.IsNullOrEmpty(encryptedMessage))
                    return BadRequest("Le message est vide ou invalide.");

                byte[] key = Encoding.UTF8.GetBytes("123456789012345678901234");
                byte[] encryptedBytes = Convert.FromBase64String(encryptedMessage); 
                
                using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
                {
                    tdes.Key = key;
                    tdes.Mode = CipherMode.ECB;
                    tdes.Padding = PaddingMode.PKCS7;

                    ICryptoTransform decryptor = tdes.CreateDecryptor();
                    byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);

                    string decryptedMessage = Encoding.UTF8.GetString(decryptedBytes);

                    Console.WriteLine($"Message déchiffré : {decryptedMessage}");

                    if (decryptedMessage.Equals("cyber", StringComparison.OrdinalIgnoreCase))
                    {
                        return Ok("true"); 
                    }
                    else
                    {
                        return Ok("false");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erreur serveur : {ex.Message}");
                return StatusCode(500, "Erreur lors du chiffrement.");
            }
        }
        [HttpPut("cryptWithAESmodeCBC")]
        public bool cryptWithAESmodeCBC()
        {
            //todo : msg chiffré avec AES en mode CBC , clé généré avec diffie hellman
            return true;
        }
        
        [HttpPut("hashWithSHA1")]
        public bool hashWithSHA1()
        {
            //todo :msg haché avec sh&1
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