using System;
using System.Linq;
using System.Security.Cryptography;

namespace Dotnet.Sigma
{
    //в качестве схемы формирования электронных подписей //shell
    public class EllipticCurveDigitalSignatureAlgo : IDisposable
    {
        private const int KEY_BYTE_SIZE = 16;
        private const int OFFSET = 0;
        public byte[] PublicKey { get; set; } // (calculated by elliptic curve) // для шифрования и проверки подписи
        private byte[] SecretKey { get; set; } // (randomly selected) // для расшифрования и подписания
        public byte[] Signature { get; set; }
        private ECDsa Algorithm { get; set; }

        public void Generate() // generates PublicKey and SecretKey
        {
            Initialize();
            SecretKey = Algorithm.ExportParameters(true).D;
            PublicKey = LogicHelper.Сoncatenate(Algorithm.ExportParameters(true).Q.X,
                Algorithm.ExportParameters(true).Q.Y);
        }

        public byte[] Sign(byte[] message)
        {
            return Signature = Algorithm.SignData(message, OFFSET, message.Length, HashAlgorithmName.SHA256);
        }

        public bool Verify(byte[] message, byte[] signature)
        {
            return Algorithm.VerifyData(message, signature, HashAlgorithmName.SHA256);
        }
        
        private void Initialize()
        {
            Algorithm ??= ECDsa.Create();
        }

        public void Dispose()
        {
            Algorithm?.Dispose();
        }
    }
}