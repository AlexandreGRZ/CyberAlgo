namespace CyberSecurity.Service.RSA;
using System.Security.Cryptography;

public class RSAUtils
{
    public static RSA LoadPublicKey(string publicKeyPath)
    {
        string publicKeyText = System.IO.File.ReadAllText(publicKeyPath);
        RSA rsa = RSA.Create();
        rsa.ImportFromPem(publicKeyText.ToCharArray());
        return rsa;
    }
    public static RSA LoadPrivateKey(string privateKeyPath)
    {
        string PrivateKeyText = System.IO.File.ReadAllText(privateKeyPath);
        RSA rsa = RSA.Create();
        rsa.ImportFromPem(PrivateKeyText.ToCharArray());
        return rsa;
    }
}