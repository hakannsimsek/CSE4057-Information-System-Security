using System;
using System.Security.Cryptography;
using System.Text;


namespace SHA256MessageAuthentication
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("enter string to hash:");
            string input = Console.ReadLine();
            Console.WriteLine($"hashed string:{Hashing.ToSHA256(input)}");
            Console.ReadLine();
        }
    }
    public class Hashing
    {
        public static string ToSHA256(string s)
        {
            using var sha256 = SHA256.Create();
            byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(s));
            var sb = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                sb.Append(bytes[i].ToString("x2"));
            }
            return sb.ToString();

        }
    }

}