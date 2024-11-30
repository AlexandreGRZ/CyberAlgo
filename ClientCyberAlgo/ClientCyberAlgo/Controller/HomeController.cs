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
             
    }
}