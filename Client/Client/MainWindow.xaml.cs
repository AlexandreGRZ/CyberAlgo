
using System.Windows;
using Client.Service;

namespace Client;

public partial class MainWindow : Window
{
    public ApiService _apiService { get; set; }
    private CryptoService _cryptoService { get; set; }
    public MainWindow()
    {
        InitializeComponent();
        _apiService = new ApiService();
        _cryptoService = new CryptoService();
    }
    public async void testApi(object sender, RoutedEventArgs routedEventArgs)
    {
        try
        {
            string arg1 = arg1TextBox.Text;
            Console.WriteLine($"texte : {arg1}");
            string url = $"https://localhost:5274/api/Home/testApi";
            string responseData = await _apiService.PutDataAsync(url, arg1);
            Console.WriteLine($"reponse : {responseData} ");
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
    }
    
    public async void Sha1(object sender, RoutedEventArgs routedEventArgs)
    {
        try
        {
            string arg1 = arg1TextBox.Text;
            Console.WriteLine($"texte avant hachage  : {arg1}");
            string  msgHash = _cryptoService.Sha1Hash(arg1);
            Console.WriteLine($"reponse : {msgHash}\t nb bits : {msgHash.Length}");
            
            string url = $"https://localhost:7129/api/Home/hashWithSHA1?param="+msgHash;
            string responseData = await _apiService.PutDataAsync(url, arg1);
            Console.WriteLine($"mdp correspond : {responseData}\t");
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
    }
    
}