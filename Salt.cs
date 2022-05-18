using System;
using System.Security.Cryptography;

namespace Dotnet.Sigma
{
    public class Salt
    {
        public static byte[] CreateSalt(int size)
        {
            byte[] buff = new byte[size];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(buff);
            };
            return buff;
        }
    }
}