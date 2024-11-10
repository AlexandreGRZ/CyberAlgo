
using System.Windows;
using Client.Service;

namespace Client;

public partial class MainWindow : Window
{
    public ApiService _apiService { get; set; }
    public MainWindow()
    {
        InitializeComponent();
        _apiService = new ApiService();
    }
    public async void testApi(object sender, RoutedEventArgs routedEventArgs)
    {
        try
        {
            string arg1 = arg1TextBox.Text;
            Console.WriteLine($"texte : {arg1}");
            string url = $"https://localhost:5274/api/Home/testApi";
            string responseData = await _apiService.PutDataAsync(url, arg1);
            Console.WriteLine($"reponse : {responseData}");
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
    }
}