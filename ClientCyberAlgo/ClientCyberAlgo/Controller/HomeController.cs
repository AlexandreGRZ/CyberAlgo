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

        [HttpPut("SendAESWithDH")]
        public async Task<string> SendAESWithDH(string arg1)
        {
            try
            {
                byte[] sharedSecret = _cryptoService.GenerateSharedSecret();
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
    }
}
