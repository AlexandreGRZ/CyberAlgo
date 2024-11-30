namespace CyberSecurity.Service.RSA;

public class RSAObjectSend
{
    public string Message { get; set; }
    public byte[] Data { get; set; }

    public RSAObjectSend(string message, byte[] data)
    {
        Message = message;
        Data = data;
    }
    
}