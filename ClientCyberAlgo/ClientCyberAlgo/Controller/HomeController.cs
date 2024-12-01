using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using ClientCyberAlgo.Service;
using ClientCyberAlgo.Service.RSA;
using CyberSecurity.Service.RSA;
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

        [HttpPut("SendHMAC-MD5")]
        public async Task<string> sendHMACMD5(string message, int randomNumber, bool authenticated)
        {
            double secretKey = await diffiehellman(randomNumber); 
            
            string hmac = _cryptoService.GenerateHmac(message, secretKey.ToString());

            if (!authenticated)
            {
                 hmac = _cryptoService.GenerateHmac(message, "999" );
            }
            Console.WriteLine("Message à envoyer : " + message);
            Console.WriteLine("HMAC généré : " + hmac);
            string url = "http://localhost:5274/api/Home/authWithHMAC?message="+message+"&hash="+hmac;
            string responseData = await _apiService.PutDataAsync(url, null);

            Console.WriteLine($"Réponse du serveur : {responseData}");
            return responseData;
            
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
               BigInteger PublicKey =  BigInteger.ModPow(5, key, 23);  //  5^key %23    => clé pub client    clePublic^key%23 
               
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
        
        [HttpPut("SendWithSh1AndRSA")]
        public async Task<string> Sha1(string arg1)
        {
            try
            {
                
                RSA publicKey = RSAUtils.LoadPublicKey("./Service/RSA/publicKey.pem");
                Console.WriteLine($"texte avant hachage  : {arg1}");
                byte[]  msgHash = Encoding.UTF8.GetBytes(_cryptoService.Sha1Hash(arg1));
                byte[] encryptedMessage = RSAUtils.SendMessageWithRSASignature(publicKey, msgHash);
                
                Console.WriteLine("Message chiffré : " + Convert.ToBase64String(encryptedMessage));
                RSAObjectSend param = new RSAObjectSend(arg1, encryptedMessage);
                string url = $"http://localhost:5274/api/Home/signedWithSHAandRSA";
                string responseData = await _apiService.PutDataAsync(url, param);
                Console.WriteLine($"mdp correspond : {responseData}\t");
                return responseData;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return "false"; 
            }
        }
        
        [HttpPut("SendWithRSAKeystore")]
        public async Task<string> RSAKeystore(string arg1)
        {
            try
            {
                KeystoreLoader keystoreLoader = new KeystoreLoader();
               // keystoreLoader.LoadCertificateFromP12("C:\\Workspace\\School\\MASI1\\CyberSecu\\Labo\\CyberAlgo\\RSAkeystore.p12","destinationPassword");
                keystoreLoader.LoadCertificateFromP12("./Service/RSA/RSAkeystore.p12","destinationPassword");
                Console.WriteLine($"texte : {arg1}");
                
                byte[] byteArray = Encoding.UTF8.GetBytes(arg1);
                if (keystoreLoader.PublicKey != null)
                {
                    byte[] bytesToSend = RSAUtils.SendMessageWithRSASignature(keystoreLoader.PublicKey, byteArray);
                    string url = $"http://localhost:5274/api/Home/cryptWithRSA";
                    
                    string responseData = await _apiService.PutDataAsync(url, bytesToSend);
                    Console.WriteLine($"reponse : {responseData} ");
                    return responseData;
                }
                else
                {
                    Console.WriteLine("keystore loader : Public Key not found");
                    return "false";
                }
                
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return "false"; 
            }
        }

        [HttpPut("sendCoucou")]
        public async Task<string> sendCoucou(string msg, int randomNumber)
        {
            double secretKey = await diffiehellman(randomNumber); // récup de la clé partagée avec diffie hellamn 

            try
            {
                KeystoreLoader keystoreLoader = new KeystoreLoader();
                // keystoreLoader.LoadCertificateFromP12("C:\\Workspace\\School\\MASI1\\CyberSecu\\Labo\\CyberAlgo\\RSAkeystore.p12","destinationPassword");
                keystoreLoader.LoadCertificateFromP12("./Service/RSA/RSAkeystore.p12", "destinationPassword");
                Console.WriteLine($"texte : {msg}");

                byte[] byteArray = Encoding.UTF8.GetBytes(msg);
                if (keystoreLoader.PublicKey != null)
                {
                    byte[] bytesToSend = RSAUtils.SendMessageWithRSASignature(keystoreLoader.PublicKey, byteArray);
                    Console.WriteLine("apres RSA : "+Convert.ToBase64String(bytesToSend));
                    
                    // calcul du hash 
                    string hmac = _cryptoService.GenerateHmac(msg, secretKey.ToString());
                    Console.WriteLine("HMAC généré : " + hmac);
                    
                    //utilisation de AES
                    byte[] sharedSecret = _cryptoService.getAESSharedKey(BigInteger.Parse(secretKey.ToString()));
                    Console.WriteLine($"Clé partagée générée avec Diffie-Hellman : {Convert.ToBase64String(sharedSecret)}");
                    string iv;
                    string encryptedMessage = _cryptoService.AesEncryptWithSharedKey(msg, sharedSecret, out iv);
                    Console.WriteLine($"Message chiffré avec AES  : {encryptedMessage}");
                    
                    //encoie vers le serveur 
                    
                    coucouModel  cc = new coucouModel(encryptedMessage, bytesToSend,hmac);
                    
                    string url = $"http://localhost:5274/api/Home/getCoucou";
                    string responseData = await _apiService.PutDataAsync(url, cc);
                    Console.WriteLine($"reponse : {responseData} ");
                    return "réponse du serveur : + " + responseData;
                }
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
            return "false";
        }
    }
}