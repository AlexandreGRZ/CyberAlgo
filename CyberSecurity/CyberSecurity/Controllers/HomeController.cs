using CyberSecurity.Service;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace CyberSecurity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class HomeController : Controller
    {
    
        private Crypto_service _crypto_service;
        private static BigInteger sharedKey  ; 
        
        public HomeController()
        {
           _crypto_service = new Crypto_service();
        }
        
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

                
                Console.WriteLine("message reçu : " + encryptedMessage);
                byte[] keyBytes = _crypto_service.getAESSharedKey(sharedKey);
                Console.WriteLine("clé partagée pour AES encryption : "+ Convert.ToBase64String(keyBytes));
                Console.WriteLine("longueur clé partagée pour AES encryption : "+ keyBytes.Length);
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

        [HttpPut("hashWithSHA1")]
        public bool hashWithSHA1(string message ,string  hash )
        {
            
            string calculatedhash =_crypto_service.Sha1Hash(message);
            Console.WriteLine($"Mot de passe haché : {calculatedhash}");
            Console.WriteLine($"hash reçu : {hash}");
            if (calculatedhash != hash)
            {
                return false;
            }
            
            return true;
        }
          
        [HttpPut("authWithHMAC")]
        public bool authWithHMAC(string message ,string  hash )
        {
             
            return _crypto_service.verifyHmac(message,hash, sharedKey.ToString());
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
        [HttpPut("diffieHellman")]
        public double diffieHellman(double  publicKey)
        {
            int random = RandomNumberGenerator.GetInt32(0, 25); // 25 pris arbitrairement
            BigInteger PublicKeyServer = BigInteger.ModPow(5, random, 23);
            Console.WriteLine("clé public serveur : "+ PublicKeyServer );
              sharedKey = BigInteger.ModPow(BigInteger.Parse(publicKey.ToString()), random, 23); 
            Console.WriteLine("clé partagée : "+ sharedKey );
            return Double.Parse(PublicKeyServer.ToString());
        }
    }
}