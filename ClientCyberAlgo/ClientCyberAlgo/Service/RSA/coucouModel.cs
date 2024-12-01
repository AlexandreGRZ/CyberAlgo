namespace ClientCyberAlgo.Service.RSA;

public class coucouModel
{
    public string Message { get; set; }
    public byte[] signature { get; set; }
    
    public string hash  { get; set; }

    public coucouModel(string message, byte[] s, string h)
    {
        Message = message;
        signature = s;
        hash = h;
    }
}