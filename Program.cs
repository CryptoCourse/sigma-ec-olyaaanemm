namespace Dotnet.Sigma
{
    class Program
    {
        static void Main(string[] args)
        {
            Person Alice = new Person("Alice");
            Person Bob = new Person("Bob");

            // === Preparation === Step 0. === Предварительный обмен ключами
            
            Alice.CreateKeyAndSendTo(Bob); // Send ECDSA Public Key  A -> B
            Bob.CreateKeyAndSendTo(Alice); // Send ECDSA Public Key  B -> A
            
            // === Sigma === Step 1. === Протокол Sigma
            
            Alice.CreateKeyAndSendTo(Bob, true); // Send ECDH Public Key  A -> B
            Bob.CreateKeyAndSendTo(Alice, true); // Send ECDH Public Key  B -> A
            
            // === Create and swap the Shared secrets
            
            Bob.CreateSecrets();
            Alice.GetSecretsFrom(Bob);
            
            // === Create and swap the Shared secrets
            
            Alice.CreateSecrets();
            Bob.GetSecretsFrom(Alice);
            
            // === Send information == Step 2. === Отправка зашифрованных данных

            Alice.SendMessage("dhsjdksjdk", Bob);
        }
    }
}