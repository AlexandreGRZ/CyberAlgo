using System.Numerics;
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
