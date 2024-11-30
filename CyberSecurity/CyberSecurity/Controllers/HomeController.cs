using System;
using System.Security.Cryptography;
using System.Text;
using CyberSecurity.Service.RSA;
using Microsoft.AspNetCore.Mvc;

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
        public bool cryptWith3DESmodeEBC()
        {
            //todo :  msg chiffré avec 3DES en mode EBC , les clés sont hardcodé
            return true;
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
        public bool signedWithSHAandRSA([FromBody] RSAObjectSend param)
        {
            //todo : msg signé avec sha 1 et RSA , clé peuvent eter hardcodé ou transmise sur le réseaux
            
            try
            {
                // Charger la clé privée pour déchiffrer la signature
                string privateKeyPath = "./Service/RSA/privateKey.pem";
                RSA privateKey = RSAUtils.LoadPrivateKey(privateKeyPath);

                // Convertir les données reçues en bytes
                byte[] decryptedHash;
                try
                {
                    // Déchiffrer les données pour obtenir le hash
                    decryptedHash = privateKey.Decrypt(param.Data, RSAEncryptionPadding.Pkcs1);
                }
                catch (CryptographicException)
                {
                    // Si la décryption échoue, cela signifie que la signature n'est pas valide
                    Console.WriteLine("Failed to decrypt data, Key Incorrect");
                    return false;
                }

                // Calculer le hash SHA-1 du message reçu
                SHA1 sha1 = SHA1.Create();
                byte[] computedHash = sha1.ComputeHash(Encoding.UTF8.GetBytes(param.Message));

                // Comparer le hash déchiffré avec le hash calculé
                bool isValid = decryptedHash.SequenceEqual(computedHash);

                if (isValid)
                {
                    Console.WriteLine("La signature et le hash sont valides.");
                    return true;
                }
                else
                {
                    Console.WriteLine("Le hash SHA-1 ne correspond pas.");
                    return false;
                }
            }
            catch (Exception ex)
            {
                return false;
            }
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