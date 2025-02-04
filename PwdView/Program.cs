using PassView;
using SQLite;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using static Community.CsharpSqlite.Sqlite3;

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
        }

        public static void GetLogins(string loginData, byte[] masterKey)
        {
            SQLiteConnection database = new SQLiteConnection(loginData, SQLiteOpenFlags.ReadOnly | SQLiteOpenFlags.OpenUri, false);

            string query = "SELECT origin_url, username_value, password_value FROM logins";
            List<SQLiteQueryRow> results = database.Query2(query, false);

            foreach (SQLiteQueryRow row in results)
            {
                byte[] passwordBytes = (byte[])row.column[2].Value;

                string password = Encoding.Default.GetString(DecryptWithKey(passwordBytes, masterKey));

                Console.WriteLine("URL       : {0}", row.column[0].Value);
                Console.WriteLine("Username  : {0}", row.column[1].Value);
                Console.WriteLine("Password  : {0}", password);
                Console.WriteLine();
            }

            database.Close();

        }

        public static List<string> SearchFiles(string path, string pattern)
        {
            var foundFiles = new HashSet<string>();

            try
            {
                var files = Directory.GetFiles(path, pattern, SearchOption.AllDirectories);

                foreach (var file in files)
                    foundFiles.Add(file);
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
