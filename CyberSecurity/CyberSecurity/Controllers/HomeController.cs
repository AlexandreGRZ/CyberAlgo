
﻿using System;
using System.Security.Cryptography;
using System.Text;
using CyberSecurity.Service.RSA;
﻿using CyberSecurity.Service;

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
                    decryptedHash = RSAUtils.ReceiveMessageWithRSASignature(privateKey, param.Data);
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
        public bool cryptWithRSA([FromBody] byte[] param)
        {
            // todo : le msg est chiffré a l'aide de RSA , la clé publique provient
            // d'un certificat save dans un keystore

            KeystoreLoader keystoreLoader = new KeystoreLoader();
            keystoreLoader.LoadCertificateFromP12("C:\\Workspace\\School\\MASI1\\CyberSecu\\Labo\\CyberAlgo\\RSAkeystore.p12","destinationPassword");

            if (keystoreLoader.PrivateKey != null)
            {
                byte[] byteArray = RSAUtils.ReceiveMessageWithRSASignature(keystoreLoader.PrivateKey, param);
                string message = Encoding.UTF8.GetString(byteArray);
                Console.WriteLine(message);
                return true;
            }
            else
            {
                Console.WriteLine("KeystoreLoader : Private key is null.");
                return false;
            }
            
            
            
        }
             
    }
}