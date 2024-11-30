﻿using System.Numerics;
using ClientCyberAlgo.Service;
using Microsoft.AspNetCore.Mvc;

namespace ClientCyberAlgo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class HomeController : Controller
    {

        public ApiService _apiService { get; set; }
        private CryptoService _cryptoService { get; set; }

        public HomeController()
        {
            _apiService = new ApiService();
            _cryptoService = new CryptoService();
        }

        [HttpPut("testApi")]
        public async Task<string> testApi(string arg1)
        {
            try
            {
                Console.WriteLine($"texte : {arg1}");
                string url = $"http://localhost:5274/api/Home/testApi";
                string responseData = await _apiService.PutDataAsync(url, arg1);
                Console.WriteLine($"reponse : {responseData} ");
                return responseData;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return "false"; 
            }
        }
    
        [HttpPut("SendHashSha1")]
        public async Task<string> Sha1(string arg1 , bool integrity)
        {
            try
            {
                
                Console.WriteLine($"texte avant hachage  : {arg1}");
                string  msgHash = _cryptoService.Sha1Hash(arg1);
                Console.WriteLine($"reponse : {msgHash}\t nb bits : {msgHash.Length}");

                if (!integrity)
                {
                    arg1 += " false";
                    Console.WriteLine($"texte apres changement  : {arg1}");
                }
                
                string url = $"http://localhost:5274/api/Home/hashWithSHA1?message="+arg1+"&hash="+msgHash;
                string responseData = await _apiService.PutDataAsync(url, null);
                Console.WriteLine($"mdp correspond : {responseData}\t");
                return responseData;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return "false";
            }
        }

        [HttpPut("SendAESWithDH")]
        public async Task<string> SendAESWithDH(string arg1, int randomNumber)
        {
            try
            {
                double secretKey = await diffiehellman(randomNumber); 
                
                byte[] sharedSecret = _cryptoService.getAESSharedKey(BigInteger.Parse(secretKey.ToString()));
                Console.WriteLine($"Clé partagée générée avec Diffie-Hellman : {Convert.ToBase64String(sharedSecret)}");

                string iv;
                string encryptedMessage = _cryptoService.AesEncryptWithSharedKey(arg1, sharedSecret, out iv);
                Console.WriteLine($"Message chiffré avec AES et clé partagée : {encryptedMessage}");

                string url = "http://localhost:5274/api/Home/cryptWithAESmodeCBC";
                string responseData = await _apiService.PutDataAsync(url, encryptedMessage);

                Console.WriteLine($"Réponse du serveur : {responseData}");
                return responseData;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erreur : {ex.Message}");
                return "Erreur lors de l'envoi";
            }
        }
        
        
        [HttpPut("Send3DES")]
        public async Task<string> Send3DES(string arg1)
        {
            try
            {
                Console.WriteLine($"Texte brut : {arg1}");

                string key = "123456789012345678901234"; 

                string encryptedMessage = _cryptoService.TripleDESEncrypt(arg1, key);
                if (string.IsNullOrEmpty(encryptedMessage))
                {
                    throw new Exception("Le chiffrement a échoué.");
                }

                Console.WriteLine($"Message chiffré avec 3DES : {encryptedMessage}");

                string url = "http://localhost:5274/api/Home/cryptWith3DESmodeEBC";
        
                string responseData = await _apiService.PutDataAsync(url, encryptedMessage);

                Console.WriteLine($"Réponse du serveur : {responseData}");
                return responseData;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erreur : {ex.Message}");
                return "Erreur lors de l'envoi";
            }
        } 
        
        [HttpPut("diffie-Hellman")]
        public async Task<double> diffiehellman(int key)
        {
            try
            {
               BigInteger PublicKey =  BigInteger.ModPow(5, key, 23); ;
               
               string url = "http://localhost:5274/api/Home/diffieHellman?publicKey="+ PublicKey;
               string responseData = await _apiService.PutDataAsync(url, null);

               Console.WriteLine($"Réponse du serveur : {responseData}");
               
               BigInteger sharedKey = BigInteger.ModPow(BigInteger.Parse(responseData), key, 23); 
               Console.WriteLine($"clé public client : {PublicKey}");
               Console.WriteLine($"clé partagé : {sharedKey}");

               return double.Parse(sharedKey.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erreur : {ex.Message}");
                return -1;
            }
        }
    }
}