using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace ASPNetCore5.Pages.Crypto
{
    public class IndexModel : PageModel
    {
        public void OnGet()
        {
        }

        [BindProperty]
        public string InputPara { get; set; }

        public IActionResult OnPost()
        {
            var encrypted = EncryptStringAES("Hello World");
            return RedirectToPage("/Crypto/ServerSide", new { id = HttpUtility.HtmlEncode(encrypted) });
        }

        public string EncryptStringAES(string plainText)
        {
            var keybytes = Encoding.UTF8.GetBytes("8056483646328763");
            var iv = Encoding.UTF8.GetBytes("8056483646328763");
            //Encrypt FROM CRIPTOJS
            var encryptvalue = EncryptStringValue(plainText, keybytes, iv);
            return Convert.ToBase64String(encryptvalue);
        }

        public static byte[] EncryptStringValue(string plainText, byte[] key, byte[] iv)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
            {
                throw new ArgumentNullException(nameof(plainText));
            }
            if (key == null || key.Length <= 0)
            {
                throw new ArgumentNullException(nameof(key));
            }
            if (iv == null || iv.Length <= 0)
            {
                throw new ArgumentNullException(nameof(key));
            }

            byte[] encrypted;
            // Create an RijndaelManaged object
            // with the specified key and IV.
            using var rijAlg = new RijndaelManaged();
            //Settings
            rijAlg.Mode = CipherMode.CBC;
            rijAlg.Padding = PaddingMode.PKCS7;
            rijAlg.FeedbackSize = 128;
            rijAlg.Key = key;
            rijAlg.IV = iv;
            //// Create a encryptor to perform the stream transform.
            var encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);
            //// Create the streams used for decryption.
            //using var msEncrypt = new MemoryStream(plainText,);
            //using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Read);
            //using var srEncrypt = new StreamReader(csEncrypt);
            //string plaintext = srEncrypt.ReadToEnd();

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {

                        //Write all data to the stream.
                        swEncrypt.Write(plainText);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }

            return encrypted;
        }

    }
}
