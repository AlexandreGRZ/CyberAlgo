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
                string url = $"https://localhost:7129/api/Home/testApi";
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
        public async Task<string> Sha1(string arg1)
        {
            try
            {
                Console.WriteLine($"texte avant hachage  : {arg1}");
                string  msgHash = _cryptoService.Sha1Hash(arg1);
                Console.WriteLine($"reponse : {msgHash}\t nb bits : {msgHash.Length}");
            
                string url = $"https://localhost:7129/api/Home/hashWithSHA1?param="+msgHash;
                string responseData = await _apiService.PutDataAsync(url, arg1);
                Console.WriteLine($"mdp correspond : {responseData}\t");
                return responseData;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return "false"; 
            }
        }
        [HttpPut("Send3DES")]
        
        public async Task<string> DES3(string arg1)
        {
            try
            {
                Console.WriteLine($"Texte brut : {arg1}");
        
                string hashedMessage = _cryptoService.Des3Crypt(arg1);
                Console.WriteLine($"Texte chiffré avec 3DES : {hashedMessage}");

                string url = $"http://localhost:5274/api/Home/cryptWith3DESmodeEBC";
                string responseData = await _apiService.PutDataAsync(url, hashedMessage);
        
                Console.WriteLine($"Réponse du serveur : {responseData}");
                return responseData;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erreur : {ex.Message}");
                return "Erreur lors de l'envoi";
            }
        } 
        [HttpPut("SendAES")]
        public async Task<string> SendAES(string arg1)
        {
            try
            {
                Console.WriteLine($"Texte brut : {arg1}");

                string key = "1234567890123456";
                string iv = "abcdef9876543210";

                string encryptedMessage = _cryptoService.AesEncrypt(arg1, key, iv);
                Console.WriteLine($"Message chiffré avec AES : {encryptedMessage}");

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
    }
}