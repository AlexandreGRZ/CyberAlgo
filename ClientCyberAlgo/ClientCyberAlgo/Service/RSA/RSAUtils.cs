namespace ClientCyberAlgo.Service.RSA;
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

    public static byte[] SendMessageWithRSASignature(RSA publicKey, byte[] message)
    {
        return publicKey.Encrypt(message, RSAEncryptionPadding.Pkcs1);
    }
    
    public static byte[] ReceiveMessageWithRSASignature(RSA privateKey, byte[] message)
    {
        return privateKey.Decrypt(message, RSAEncryptionPadding.Pkcs1);
    }
    
}