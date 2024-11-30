using System.Security.Cryptography;
using ClientCyberAlgo.Service;
using ClientCyberAlgo.Service.RSA;
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
                string url = $"http://localhost:7129/api/Home/testApi";
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
    
        [HttpPut("SendWithSh1AndRSA")]
        public async Task<string> Sha1(string arg1)
        {
            try
            {
                
                RSA publicKey = RSAUtils.LoadPublicKey("./Service/RSA/publicKey.pem");
                Console.WriteLine($"texte avant hachage  : {arg1}");
                byte[]  msgHash = _cryptoService.Sha1HashByte(arg1);
                
                byte[] encryptedMessage = publicKey.Encrypt(msgHash, RSAEncryptionPadding.Pkcs1);
                
                Console.WriteLine("Message chiffré : " + Convert.ToBase64String(encryptedMessage));
                RSAObjectSend param = new RSAObjectSend(arg1, encryptedMessage);
                string url = $"http://localhost:7129/api/Home/signedWithSHAandRSA";
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
             
    }
}