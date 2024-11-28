namespace CyberSecurity.Service;
using System.Security.Cryptography;
using System.Text;
public class Crypto_service
{
      
      public string Sha1Hash(string text)
         {
             byte[] textBytes = Encoding.UTF8.GetBytes(text);
             using (SHA1 sha1 = SHA1.Create())
             {
                 byte[] hashBytes = sha1.ComputeHash(textBytes);
                 return BitConverter.ToString(hashBytes).Replace("-", "").ToLower(); // s'affiche sous le format XX-XX-XX... on retire donc les - 
                    
             }
         }
}