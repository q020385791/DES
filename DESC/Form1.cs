using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace DESC
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void btnEncrypt_Click(object sender, EventArgs e)
        {
            Security Sec = new Security();
            txtResult.Text =Sec.Encrypt(txtInput.Text);
        }
        private void btnDecrypt_Click(object sender, EventArgs e)
        {
            Security Sec = new Security();
            txtResult.Text = Sec.Decrypt(txtInput.Text, Sec._Key,Sec._IV);
        }

        public class Security 
        {
            public string _Key;
            public string _IV;


            public string Key 
            {
                set 
                {
                    _Key = value.Length == 8 ? value : "!@#$%^&*";
                }
            }

            public string IV 
            {
                set 
                {
                    _IV = value.Length == 8 ? value : ")(*&^%$#";
                }
            }
            public Security()
            {
                _Key = "!@#$%^&*";
                _IV = ")(*&^%$#";

            }
            public Security(string newKey, string newIV)
            {
                this.Key = newKey;
                this.IV = newIV;
            }
            public string Encrypt(string value)
            {
                return Encrypt(value, _Key, _IV);
            }
            private string Encrypt(string pToEncrypt, string sKey, string sIV) 
            {
                StringBuilder ret = new StringBuilder();
                //字元轉換為Byte
              

                using (DESCryptoServiceProvider des=new DESCryptoServiceProvider())
                {
                    byte[] inputByteArray = Encoding.Default.GetBytes(pToEncrypt);
                    //加密金鑰
                    des.Key = ASCIIEncoding.ASCII.GetBytes(sKey);
                    des.IV= ASCIIEncoding.ASCII.GetBytes(sIV);
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(inputByteArray, 0, inputByteArray.Length);
                            cs.FlushFinalBlock();
                        }
                        //輸出資料
                        foreach (byte b in ms.ToArray())
                            ret.AppendFormat("{0:X2}", b);
                    }

                }
                return ret.ToString();
            }

            public string Decrypt(string pToDecrypt, string sKey, string sIV) 
            {
                using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
                {
                    byte[] inputByteArray = new byte[pToDecrypt.Length / 2];
                    //反轉
                    for (int x = 0; x < pToDecrypt.Length / 2; x++)
                    {
                        int i = (Convert.ToInt32(pToDecrypt.Substring(x * 2, 2), 16));
                        inputByteArray[x] = (byte)i;
                    }
                    des.Key = ASCIIEncoding.ASCII.GetBytes(sKey);
                    des.IV = ASCIIEncoding.ASCII.GetBytes(sIV);
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            //例外處理
                            try
                            {
                                cs.Write(inputByteArray, 0, inputByteArray.Length);
                                cs.FlushFinalBlock();
                                //輸出資料
                                return System.Text.Encoding.Default.GetString(ms.ToArray());
                            }
                            catch (CryptographicException)
                            {
                                return "N/A";
                            }
                        }
                    }
                }

            }
            public bool ValidateString(string EnString, string FoString)
            {
                //呼叫Decrypt解密
                //判斷是否相符
                //回傳結果
                return Decrypt(EnString, _Key, _IV) == FoString.ToString() ? true : false;
            }
        }

       
    }
}
