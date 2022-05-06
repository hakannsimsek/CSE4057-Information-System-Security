using System;
using static System.Console;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;


namespace SignAndVerifyDigitalSignature
{
    class Program
    {
        static void Main(string[] args)
        {
            Protection protection = new Protection();
            string dataFile;
            string signedFile;
            try
            {
                if (args.Length < 2)
                {
                    dataFile = @"text.txt";
                    signedFile = "SignedFile.enc";

                    Write("Write some text to sign:");
                    string text = ReadLine();
                    if (!File.Exists(dataFile))
                    {
                        using(StreamWriter sw = File.CreateText(dataFile))
                        {
                            sw.WriteLine(text);
                        }
                    }
                    byte[] secretKey = new byte[64];

                    using(RNGCryptoServiceProvider rng=new RNGCryptoServiceProvider())
                    {
                        rng.GetBytes(secretKey);
                        protection.SignFile(secretKey, dataFile, signedFile);
                        protection.VerifyFile(secretKey, signedFile);

                    }

                }
                else
                {
                    dataFile = args[0];
                    signedFile = args[1];
                }
            }
            catch (Exception ex)
            {
                WriteLine(Environment.NewLine + ex.Message);
            }

            WriteLine(Environment.NewLine + "You Signed and verified the file! Check files in the directory");
            WriteLine(Environment.NewLine + "Press any key to continue...");
            ReadKey();

        }
    }
    class Protection
    {
        //Computes a keyed hash for a source file and creates a target file
        //with the keyed hash prepared to the contents of the source file

        public void SignFile(byte[] key, string sourceFile, string destFile)
        {
            using (HMACSHA256 hmac =new HMACSHA256(key))
            {
                using (FileStream inStream=new FileStream(sourceFile, FileMode.Open))
                {
                    using(FileStream outStream=new FileStream(destFile, FileMode.Create))
                    {
                        byte[] hashValue = hmac.ComputeHash(inStream);
                        inStream.Position = 0;
                        outStream.Write(hashValue, 0, hashValue.Length);
                        int bytesRead;
                        byte[] buffer = new byte[1024];
                        do
                        {
                            bytesRead = inStream.Read(buffer, 0, 1024);
                            outStream.Write(buffer, 0, bytesRead);

                        } while (bytesRead > 0);
                    }
                }
            }
            return;
        }
        public bool VerifyFile(byte[] key,string sourceFile)
        {
            bool err = false;

            using(HMACSHA256 hmac=new HMACSHA256(key))
            {
                byte[] storedHash = new byte[hmac.HashSize / 8];
                using (FileStream inStream = new FileStream(sourceFile, FileMode.Open))
                {
                    inStream.Read(storedHash, 0, storedHash.Length);
                    byte[] computedHash = hmac.ComputeHash(inStream);
                    for(int i = 0; i < storedHash.Length; i++)
                    {
                        if(computedHash[i] != storedHash[i])
                        {
                            err = true;

                        }
                    }
                }

            }
            if (err)
            {
                WriteLine(Environment.NewLine + "Hash values differ!Signed file has been tampered with");
                return false;
            }
            else
            {
                WriteLine(Environment.NewLine + "Hash values agree! No tampering occured");
                return true;

            }
        }

    }
}
