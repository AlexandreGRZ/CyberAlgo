<<<<<<< HEAD
﻿namespace CyberSecurity.Service;
using System.Security.Cryptography;
using System.Text;
public class Crypto_service
{
      
      public string Sha1Hash(string text)
         {
             byte[] textBytes = Encoding.UTF8.GetBytes(text);
             dusing (SHA1 sha1 = SHA1.Create())
             {
                 byte[] hashBytes = sha1.ComputeHash(textBytes);
                 return BitConverter.ToString(hashBytes).Replace("-", "").ToLower(); // s'affiche sous le format XX-XX-XX... on retire donc les - 
                    
             }
         }
}
=======
﻿using System.Numerics;
using System.Security.Cryptography;

namespace CyberSecurity.Service;

public class Crypto_service
{
    public byte[] getAESSharedKey(BigInteger key)
    {
        byte[] keyBytes = key.ToByteArray();

        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] hashedKey = sha256.ComputeHash(keyBytes);
            return hashedKey;
        }

    }
}
>>>>>>> refs/heads/aes-algo
