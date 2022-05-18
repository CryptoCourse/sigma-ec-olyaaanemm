using System;
using System.Security.Cryptography;

namespace Dotnet.Sigma
{
    //в качестве схемы формирования общего секрета
    public class EllipticCurveDiffieHellman : IDisposable
    {
        public ECDiffieHellmanPublicKey PublicKey { get; internal set;}
        public byte[] SecretKey { get; set; }
        private ECDiffieHellman Algorithm { get; set; }

        public EllipticCurveDiffieHellman()
        {
            Initialize();
        }

        public void Generate()
        {
            Initialize();
        }

        public byte[] GetSecret(byte[] secretKey, ECDiffieHellmanPublicKey publicKey)
        {
            int n; 
            Algorithm.ImportECPrivateKey(secretKey, out n);
            return Algorithm.DeriveKeyMaterial(publicKey);
        }

        private void Initialize()
        {
            Algorithm ??= ECDiffieHellman.Create();
            PublicKey = Algorithm.PublicKey;
            SecretKey = Algorithm.ExportECPrivateKey();
        }

        public void Dispose()
        {
            Algorithm?.Dispose();
        }
    }
}