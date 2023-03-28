using System.Security.Cryptography; // AES, CryptoStream, Rfc2898DeriveBytes
using System.Text; // UTF8 Encoding
using System; // Convert

namespace AbetApi.Security {

    public class Hash {

        private readonly string _salt;
        private readonly int _iterations;

        public Hash() {
            _salt = Environment.GetEnvironmentVariable("HASH_SALT"); // the key 
            _iterations = Convert.ToInt32(Environment.GetEnvironmentVariable("HASH_ITERATIONS")); // the number of times the hash will be performed
        }

        public string Encrypt(string text) {

            using (var sha256 = SHA256.Create()) { // using instance of SHA256 algorithm as sha256
                byte[] hash = Encoding.UTF8.GetBytes(text + _salt); // append the salt and convert to bytearray

                for (int i = 0; i < _iterations; i++) // for n iterations...
                    hash = sha256.ComputeHash(hash); // hash once using sha256

                return Convert.ToBase64String(hash); // return hashed result as (base64) string

            }
        
        }

        public string Decrypt(string hash) {

            using (var sha256 = SHA256.Create()) { // using instance of SHA256 algorithm as sha256
                byte[] decodedHash = Convert.FromBase64String(hash); // convert from (base64) string to bytearray
                byte[] originalHash = Encoding.UTF8.GetBytes(Convert.ToBase64String(decodedHash) + _salt); // append the salt and convert to bytearray

                for (int i = 0; i < _iterations; i++) // for n iterations...
                    originalHash = sha256.ComputeHash(originalHash); // unhash once using sha256

                return Encoding.UTF8.GetString(originalHash); // return hashed result as (UTF-8) string

            }

        }

    }

}
