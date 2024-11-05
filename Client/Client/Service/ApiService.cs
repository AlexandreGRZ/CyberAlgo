using System.Net.Http;

using System.Diagnostics;
using System.Text;
using Newtonsoft.Json;
namespace Client.Service
{
    public class ApiService
    {
        private static readonly HttpClient _httpClient = new HttpClient();

        public async Task<string> PutDataAsync(string url, object data)
        {
            try
            {
                string jsonData = JsonConvert.SerializeObject(data);
                HttpContent content = new StringContent(jsonData, Encoding.UTF8, "application/json");
                Debug.WriteLine(jsonData);
                HttpResponseMessage response = await _httpClient.PutAsync(url, content);
                Debug.WriteLine(response);
                response.EnsureSuccessStatusCode();

                string responseData = await response.Content.ReadAsStringAsync();
                Debug.WriteLine(responseData);
                return responseData;
            }
            catch (HttpRequestException e)
            {       
                Console.WriteLine($"Erreur de requête HTTP: {e.Message}");
                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erreur : {ex.Message}");
                return null;
            }
        }
       
    }

}