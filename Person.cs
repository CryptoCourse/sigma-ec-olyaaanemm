using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Dotnet.Sigma
{
    public class Person : IDisposable
    {
        private const int R_SIZE = 128; // bits -> in bytes 16 
        private string Name { get; }
        private Dictionary<Man, byte[]> EcdsaPublicKeys { get; set; }
        private Dictionary<Man, ECDiffieHellmanPublicKey> EcdhPublicKeys { get; set; }
        private Dictionary<Man, byte[]> R { get; set; }
        private EllipticCurveDigitalSignatureAlgo Ecdsa { get; set; }
        private byte[] EcdhSecretKey { get; set; }
        private byte[] MacKey { get; set; }
        private byte[] EncryptionKeys { get; set; }
        private ICryptoTransform Aes128Encryptor { get; set; }
        
        private byte[] Tag { get; set; }
        private byte[] Sign { get; set; }

        public Person(string name)
        {
            Name = name;
            Initialize();
        }

        public void CreateKeyAndSendTo(Person human, bool sendR = false)
        {
            if (sendR)
            {
                using (EllipticCurveDiffieHellman ecdh = new EllipticCurveDiffieHellman())
                {
                    ecdh.Generate();
                    
                    EcdhPublicKeys[Man.Me] = ecdh.PublicKey;
                    EcdhSecretKey = ecdh.SecretKey;
                    
                    R[Man.Me] = Salt.CreateSalt(R_SIZE / 8);
                    human.GetPublicKey(ecdh.PublicKey, R[Man.Me]); 
                }
            }
            else
            {
                Ecdsa.Generate();
                EcdsaPublicKeys[Man.Me] = Ecdsa.PublicKey;
                human.GetPublicKey(Ecdsa.PublicKey); 
            }
        }

        private void GetPublicKey(ECDiffieHellmanPublicKey key, byte[] r)
        {
            EcdhPublicKeys[Man.Another] = key;
            R[Man.Another] = r;
        }
        private void GetPublicKey(byte[] key)
        {
            EcdsaPublicKeys[Man.Another] = key;
        }

        public void CreateSecrets()
        {
            var commonR = LogicHelper.Xor(R[Man.Me], R[Man.Another]);
            using (HMACSHA256 hmac = new HMACSHA256())
            {
                MacKey = hmac.ComputeHash(commonR, 0, commonR.Length);
                hmac.Key = MacKey;
                Tag = hmac.TransformFinalBlock(Encoding.UTF8.GetBytes(Name), 
                    0, Encoding.UTF8.GetBytes(Name).Length);
            }

            using (EllipticCurveDiffieHellman ecdh = new EllipticCurveDiffieHellman())
            {
                EncryptionKeys = ecdh.GetSecret(EcdhSecretKey, EcdhPublicKeys[Man.Another]);
            }
            
            Sign = Ecdsa.Sign(
                LogicHelper.Сoncatenate(EcdhPublicKeys[Man.Me].ToByteArray(), 
                    EcdhPublicKeys[Man.Another].ToByteArray()));
        }

        public void GetSecretsFrom(Person human)
        {
            VerifyMac(human.Tag, Encoding.UTF8.GetBytes(human.Name));

            Ecdsa.Verify(LogicHelper.Сoncatenate(EcdhPublicKeys[Man.Me].ToByteArray(),
                EcdhPublicKeys[Man.Another].ToByteArray()), human.Sign);
        }

        private void VerifyMac(byte[] otherTag, byte[] otherIndex)
        {
            var commonR = LogicHelper.Xor(R[Man.Me], R[Man.Another]);
            using (HMACSHA256 hmac = new HMACSHA256())
            {
                MacKey = hmac.ComputeHash(commonR, 0, R_SIZE);
                hmac.Key = MacKey;

                var possibleTag  = hmac.ComputeHash(otherIndex, 0, otherIndex.Length);

                if (!LogicHelper.AreEqual(possibleTag, otherTag))
                {
                    throw new AggregateException("Incorrect mac for signature!");
                }
            }
        }

        public void SendMessage(string message, Person to)
        {
            var byteMessage =  Encoding.UTF8.GetBytes(message);
            using (Aes aes128 = Aes.Create())
            {
                aes128.Key = EncryptionKeys;
                aes128.Padding = PaddingMode.None;
                aes128.Mode = CipherMode.CFB;
                Aes128Encryptor = aes128.CreateEncryptor();

                var encMessage = Aes128Encryptor.TransformFinalBlock(byteMessage, 0, byteMessage.Length);
                using (HMACSHA256 hmac = new HMACSHA256())
                {
                    hmac.Key = MacKey;
                    var tag =  hmac.TransformFinalBlock(encMessage, 0, byteMessage.Length);
                    to.GetMessage(encMessage, tag);
                }
            }
        }

        private void GetMessage(byte[] encMessage, byte[] tag)
        {
            using (Aes aes128 = Aes.Create())
            {
                aes128.Key = EncryptionKeys;
                aes128.Padding = PaddingMode.None;
                aes128.Mode = CipherMode.CFB;
                Aes128Encryptor = aes128.CreateDecryptor();
                
                using (HMACSHA256 hmac = new HMACSHA256())
                {
                    hmac.Key = MacKey;
                    var possibleTag = hmac.TransformFinalBlock(encMessage, 0, encMessage.Length);
                    if (!LogicHelper.AreEqual(possibleTag, tag))
                    {
                        throw new ArgumentException("The massage was changed!");
                    }
                }
                var decMessage = Aes128Encryptor.TransformFinalBlock(encMessage, 0, encMessage.Length);
            }
        }

        private void Initialize()
        {
            Ecdsa = new EllipticCurveDigitalSignatureAlgo();
            EcdsaPublicKeys = new Dictionary<Man, byte[]>();
            EcdhPublicKeys = new Dictionary<Man, ECDiffieHellmanPublicKey>();
            R = new Dictionary<Man, byte[]>();
        }
        
        public void Dispose()
        {
            Aes128Encryptor?.Dispose();
        }
    }
}