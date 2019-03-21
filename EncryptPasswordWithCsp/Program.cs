using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EncryptPasswordWithCsp
{
    class Program
    {
        static string filePath = Path.Combine(Directory.GetCurrentDirectory(), "config.txt");
        const string CONTAINER_NAME = "HamRadioApplication";
        static CspParameters CspParameters => new CspParameters(1)
        {
            KeyContainerName = CONTAINER_NAME,
            Flags = CspProviderFlags.UseMachineKeyStore,
            ProviderName = "Microsoft Strong Cryptographic Provider"
        };

        static void Main(string[] args)
        {
            Console.WriteLine("Type in your password");

            string password = Console.ReadLine();

            Console.Clear();

            byte[] encodedPassword = Encoding.UTF8.GetBytes(password);
            byte[] encryptedPassword = EncrypyData(encodedPassword);
            string base64EncryptedPassword = Convert.ToBase64String(encryptedPassword);

            File.WriteAllText(filePath, base64EncryptedPassword);

            Console.WriteLine("Encrypted password written to file as a base 64 string.");
            Console.ReadKey();

            base64EncryptedPassword = File.ReadAllText(filePath);
            byte[] decryptedPassword = DecryptData(Convert.FromBase64String(base64EncryptedPassword));
            string decodedPassword = Encoding.UTF8.GetString(decryptedPassword);

            Console.WriteLine($"Your password is {decodedPassword}");

            Console.ReadKey();
        }

        static void DeleteKeyContainerFromMachineKeyStore()
        {
            using (var rsa = new RSACryptoServiceProvider(CspParameters) { PersistKeyInCsp = false })
                rsa.Clear();
        }

        static byte[] EncrypyData(byte[] data)
        {
            using (var rsa = new RSACryptoServiceProvider(2048, CspParameters) { PersistKeyInCsp = true })
                return rsa.Encrypt(data, false);
        }

        static byte[] DecryptData(byte[] data)
        {
            using (var rsa = new RSACryptoServiceProvider(2048, CspParameters))
                return rsa.Decrypt(data, false);
        }
    }
}
