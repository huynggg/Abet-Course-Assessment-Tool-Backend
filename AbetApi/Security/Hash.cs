using System.Security.Cryptography; // AES, CryptoStream, Rfc2898DeriveBytes
using System.Text; // UTF8 Encoding
using System; // Convert

namespace AbetApi.Security {

    public class Hash {

        public static string Encrypt(string text) {

            string _SALT = Environment.GetEnvironmentVariable("HASH_SALT"); // the key 
            int _ITERATIONS = Convert.ToInt32(Environment.GetEnvironmentVariable("HASH_ITERATIONS")); // the number of times the hash will be performed

            using (var sha256 = SHA256.Create()) { // using instance of SHA256 algorithm as sha256
                byte[] hash = Encoding.UTF8.GetBytes(text + _SALT); // append the salt and convert to bytearray

                for (int i = 0; i < _ITERATIONS; i++) // for n iterations...
                    hash = sha256.ComputeHash(hash); // hash once using sha256

                return Convert.ToBase64String(hash); // return hashed result as (base64) string

            }
        
        }

        public static string Decrypt(string hash) {

            string _SALT = Environment.GetEnvironmentVariable("HASH_SALT"); // the key 
            int _ITERATIONS  = Convert.ToInt32(Environment.GetEnvironmentVariable("HASH_ITERATIONS")); // the number of times the hash will be performed

            using (var sha256 = SHA256.Create()) { // using instance of SHA256 algorithm as sha256
                byte[] decodedHash = Convert.FromBase64String(hash); // convert from (base64) string to bytearray
                byte[] originalHash = Encoding.UTF8.GetBytes(Convert.ToBase64String(decodedHash) + _SALT); // append the salt and convert to bytearray

                for (int i = 0; i < _ITERATIONS; i++) // for n iterations...
                    originalHash = sha256.ComputeHash(originalHash); // unhash once using sha256

                return Encoding.UTF8.GetString(originalHash); // return hashed result as (UTF-8) string

            }

        }

    }

}
