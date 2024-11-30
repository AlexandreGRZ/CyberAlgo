using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CyberSecurity.Service.RSA;

public class KeystoreLoader
{
    
    public System.Security.Cryptography.RSA? PublicKey { get; set; }
    public System.Security.Cryptography.RSA? PrivateKey { get; set; }
    
    public void LoadCertificateFromP12(string p12FilePath, string password)
    {
        // Charger le fichier .p12
        X509Certificate2 certificate = new X509Certificate2(p12FilePath, password, 
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

        // Extraire la clé publique
        PublicKey = certificate.GetRSAPublicKey();

        // Extraire la clé privée
        PrivateKey = certificate.GetRSAPrivateKey();

        Console.WriteLine("Certificat chargé avec succès !");
        Console.WriteLine($"Sujet : {certificate.Subject}");
        Console.WriteLine($"Clé publique : {PublicKey}");
        
    }

    public KeystoreLoader()
    {
        
    }
    
}