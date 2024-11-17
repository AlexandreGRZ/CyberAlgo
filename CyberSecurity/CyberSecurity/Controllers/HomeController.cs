using CyberSecurity.Service;
using Microsoft.AspNetCore.Mvc;

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
        public bool cryptWithAESmodeCBC()
        {
            //todo : msg chiffré avec AES en mode CBC , clé généré avec diffie hellman
            return true;
        }
        
        [HttpPut("hashWithSHA1")]
        public bool hashWithSHA1(string param)
        {
            // pour vérifier que le hachage est correct on rehash de ce coté avec une valeur que on connait
           // un hash peut coorespondre a 2 valeurs en entré ( collision ) 
           // donc aucun moyen detre sur de  trouver le mdp via un hash masi on peut trouver un ensemble de valeur
            string password = "cyber";
            string storedHash =_cryptoService.Sha1Hash(password);

            Console.WriteLine($"Mot de passe haché : {storedHash}");
            Console.WriteLine($"hash reçu : {param}");

            if (storedHash != param)
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