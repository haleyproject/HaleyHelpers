using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Collections;
using System.Threading.Tasks;
using System.Management;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security;
using System.Runtime.InteropServices;
using System.Xml;
using Haley.Internal;
using Haley.Models;
using Haley.Enums;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Haley.Utils
{
    public static partial class EncryptionUtils
    {
        #region Nested
        public static class Symmetric {
            public static (string key, string salt) Encrypt(FileInfo file, string save_path, string _key = null, string _salt = null) {
                try {
                    if (!file.Exists) return (null, null); //File doesn't exist

                    byte[] _file_bytes = File.ReadAllBytes(file.FullName);
                    var _result = Encrypt(_file_bytes, _key, _salt);

                    if (save_path == null) {
                        //Store in same file path with an extension.
                        string _new_name = Path.GetFileNameWithoutExtension(file.FullName) + "_Encrypted";
                        save_path = Path.Combine(file.DirectoryName, _new_name + Path.GetExtension(file.FullName));
                    }

                    //We need to write this data to a file.
                    File.WriteAllBytes(save_path, _result.value); //We either write it to same file or to new filepath.
                    return (Convert.ToBase64String(_result.key), Convert.ToBase64String(_result.salt));
                } catch (Exception ex) {
                    throw ex;
                }
            }
            public static (string value, string key, string salt) Encrypt(string to_encrypt, int key_bits = 512, int salt_bits = 512) {
                try {
                    byte[] encrypt_byte = Encoding.UTF8.GetBytes(to_encrypt);
                    var result = Encrypt(encrypt_byte, key_bits, salt_bits);

                    return (Convert.ToBase64String(result.value), Convert.ToBase64String(result.key), Convert.ToBase64String(result.salt));
                } catch (Exception) {
                    throw;
                }
            }
            public static (byte[] value, byte[] key, byte[] salt) Encrypt(byte[] to_encrypt, int key_bits = 512, int salt_bits = 512) {
                try {
                    byte[] _key = HashUtils.GetRandomBytes(key_bits).bytes; //Get random Key
                    byte[] _iv = HashUtils.GetRandomBytes(salt_bits).bytes; //Get random salt

                    return Encrypt(to_encrypt, _key, _iv);
                } catch (Exception) {
                    throw;
                }
            }
            public static (string value, string key, string salt) Encrypt(string to_encrypt, string key, string salt) {
                try {
                    byte[] encrypt_byte = Encoding.UTF8.GetBytes(to_encrypt);
                    var result = Encrypt(encrypt_byte, key, salt);
                    return (Convert.ToBase64String(result.value), Convert.ToBase64String(result.key), Convert.ToBase64String(result.salt));
                } catch (Exception ex) {
                    throw ex;
                }

            }
            public static (byte[] value, byte[] key, byte[] salt) Encrypt(byte[] to_encrypt, string key, string salt) {
                try {
                    if (key == null && salt == null) return Encrypt(to_encrypt);
                    byte[] _key;
                    byte[] _salt;

                    //GET KEY
                    if (key == null) {
                        _key = HashUtils.GetRandomBytes(256).bytes;
                    } else if (!key.IsBase64()) {
                        _key = Encoding.UTF8.GetBytes(key);
                    } else {
                        _key = Convert.FromBase64String(key);
                    }

                    //GET SALT
                    if (salt == null) {
                        _salt = HashUtils.GetRandomBytes(256).bytes;
                    } else if (!salt.IsBase64()) {
                        _salt = Encoding.UTF8.GetBytes(salt);
                    } else {
                        _salt = Convert.FromBase64String(salt);
                    }

                    return Encrypt(to_encrypt, _key, _salt);
                } catch (Exception) {
                    throw;
                }
            }
            public static (byte[] value, byte[] key, byte[] salt) Encrypt(byte[] to_encrypt, byte[] _key, byte[] _iv) //Thisis just a proxy Method for the internal class
            {
                try {
                    return (EncryptionHelper.AES.Execute(to_encrypt, _key, _iv, true), _key, _iv);
                } catch (Exception) {
                    throw;
                }
            }
            public static string Decrypt(string to_decrypt, string key, string salt) {
                try {
                    if (!to_decrypt.IsBase64()) throw new ArgumentException($@"Input not in base 64 format");
                    return Encoding.UTF8.GetString(Decrypt(Convert.FromBase64String(to_decrypt), key, salt)); //Because, when decryptd, its not the base 64 byte. Its normal string which is in byte format.
                } catch (Exception) {
                    throw;
                }
            }
            public static void Decrypt(FileInfo file, string key, string iv, string save_path) {
                try {
                    //Key, iv, todecrypt: all should be in base 64 format. do a validation to check if the inputs are in base 64 format.

                    if (!file.Exists) throw new ArgumentNullException("File doesn't exist");
                    byte[] to_decrypt = File.ReadAllBytes(file.FullName);
                    var _decryptd_bytes = Decrypt(to_decrypt, key, iv);

                    if (save_path == null) {
                        //Store in same file path with an extension.
                        string _new_name = Path.GetFileNameWithoutExtension(file.FullName) + "_DeCrypted";
                        save_path = Path.Combine(file.DirectoryName, _new_name + Path.GetExtension(file.FullName));
                    }

                    File.WriteAllBytes(save_path, _decryptd_bytes);
                } catch (Exception ex) {
                    throw ex;
                }
            }
            public static byte[] Decrypt(byte[] to_decrypt, string key, string salt) {
                try {
                    byte[] _key;
                    byte[] _salt;

                    //GET KEY
                    if (key.IsBase64()) {
                        _key = Convert.FromBase64String(key);
                    } else {
                        _key = Encoding.UTF8.GetBytes(key);    
                    }

                    //GET IV
                    if (salt.IsBase64()) {
                        _salt = Convert.FromBase64String(salt);
                    } else {
                        _salt = Encoding.UTF8.GetBytes(salt);
                    }

                    return EncryptionHelper.AES.Execute(to_decrypt, _key, _salt, false);
                } catch (Exception ex) {
                    throw ex;
                }
            }


        }
        public static partial class ASymmetric {
            public static (string public_key, string private_key) GetXMLKeyPair() {
                try {
                    return EncryptionHelper.RSA.GetXMLKeyPair();
                } catch (Exception) {
                    throw;
                }
            }
            public static (string value, string public_key, string private_key) Encrypt(string to_encrypt) {
                //User doesn't have any Key
                try {
                    var kvp = GetXMLKeyPair();
                    return (Encrypt(to_encrypt, kvp.private_key), kvp.public_key, kvp.private_key);
                } catch (Exception) {
                    throw;
                }
            }
            public static string Encrypt(string to_encrypt, string public_key) {
                //We assume that the public Key and private Key are already with the software
                try {
                    //Asymmetric keys are in xml format.
                    byte[] _to_encrypt_bytes = Encoding.UTF8.GetBytes(to_encrypt);
                    var _encrypted = Encrypt(_to_encrypt_bytes, public_key);
                    return Convert.ToBase64String(_encrypted);
                } catch (Exception) {
                    throw;
                }
            }
            public static byte[] Encrypt(byte[] to_encrypt, string public_key) {
                try {
                    return EncryptionHelper.RSA.Execute(to_encrypt, public_key, true);
                } catch (Exception) {
                    throw;
                }
            }
            public static string Decrypt(string to_decrypt, string private_key) {
                try {
                    //The string coming in is a base 64 string.
                    if (!to_decrypt.IsBase64()) throw new ArgumentException("Input not in base 64 format");
                    var result = Decrypt(Convert.FromBase64String(to_decrypt), private_key);
                    return Encoding.UTF8.GetString(result); //Since result is not in base 64 format.
                } catch (Exception) {
                    throw;
                }
            }
            public static byte[] Decrypt(byte[] to_decrypt, string private_key) {
                try {
                    return EncryptionHelper.RSA.Execute(to_decrypt, private_key, false);
                } catch (Exception) {
                    throw;
                }
            }
        }
        public static class XML {
            public static void Sign(XmlDocument input_doc, out XmlDocument output_doc, string _private_key) {
                try {
                    EncryptionHelper.XML.Sign(input_doc, out output_doc, _private_key);
                } catch (Exception) {
                    throw;
                }
            }
            public static void Verify(XmlDocument input_doc, string _public_key, out bool _status) {
                try {
                    EncryptionHelper.XML.Verify(input_doc, _public_key, out _status);
                } catch (Exception) {
                    throw;
                }
            }
        }
        public static class K2017SE {
            public static (string value, List<K2Sequence> key) Execute(string input_text, List<K2Sequence> sequences) {
                if (string.IsNullOrEmpty(input_text) || sequences == null || sequences.Count == 0) return (null, null);
                string to_execute = input_text;
                foreach (var _seq in sequences) {
                    to_execute = Execute(to_execute, _seq);
                }

                List<K2Sequence> key = sequences.ChangeDirection(true).ToList();
                return (to_execute, key);
            }

            public static string Execute(string input_text, K2Sequence sequence) {
                return EncryptionHelper.K2017SE.Execute(input_text, sequence);
            }
        }

        #endregion

        #region Extensions
        public static string Decrypt(this string to_decrypt, string key, string salt) {
            return Symmetric.Decrypt(to_decrypt, key, salt);
        }

        public static (string value, string key, string salt) Encrypt(this string to_encrypt, string key, string salt) {
            return Symmetric.Encrypt(to_encrypt, key, salt);
        }

        public static (string key, string salt) Encrypt(this FileInfo file, string save_path, string _key = null, string _salt = null) {
            return Symmetric.Encrypt(file,save_path, _key, _salt);  
        }

        public static void Decrypt(this FileInfo file, string key, string iv, string save_path) {
             Symmetric.Decrypt(file,key, iv, save_path);
        }

        public static (string value, string public_key, string private_key) RSAEncrypt(this string to_encrypt) {
            return ASymmetric.Encrypt(to_encrypt);
        }
        public static string RSAEncrypt(this string to_encrypt, string public_key) {
            return ASymmetric.Encrypt(to_encrypt,public_key);
        }

        public static string RSADecrypt(this string to_decrypt, string private_key) {
            return ASymmetric.Decrypt(to_decrypt,private_key);
        }

        public static XmlDocument Sign(this XmlDocument input_doc, string _private_key) {
            XML.Sign(input_doc,out var result, _private_key);
            return result;
        }
        public static bool Verify(this XmlDocument input_doc, string _public_key) {
            XML.Verify(input_doc, _public_key, out var result);
            return result;
        }

        public static string Sign(this string payload, string signatureKey, HashMethod method = HashMethod.Sha256, bool appendInput = true, Dictionary<string,string> headerComponents = null, string encryptKey = null) {
            string toSign = payload;
            //For the given input, generate a signature with the ShaSignatureKey
            if (string.IsNullOrWhiteSpace(toSign)) return null;

            //We need base64 for sure.
            if (!toSign.IsBase64()) {
                toSign = Convert.ToBase64String(Encoding.UTF8.GetBytes(toSign));
            }

            //Encrypt after the base64.
            if (!string.IsNullOrWhiteSpace(encryptKey)) {
                var eKey = encryptKey.ComputeHash(HashMethod.Sha256, false);
               toSign = EncryptionUtils.Encrypt(toSign, eKey, eKey).value;
            }

            toSign = toSign.SanitizeBase64();

            StringBuilder sb = new StringBuilder();
            var header = new Dictionary<string, string> {
                ["alg"] = method.ToString()
            };

            if (headerComponents != null) {
                foreach (var item in headerComponents) {
                    if (!header.ContainsKey(item.Key)) {
                        header.Add(item.Key, item.Value);
                    }
                }
            }

            sb.Append(header.ToJson().ToBase64().SanitizeBase64()); //Header
            sb.Append($@".{toSign}"); //payload

            var signature = HashUtils.ComputeSignature(sb.ToString(), signatureKey, method);
            signature = signature.SanitizeBase64();
            if (appendInput) {
                sb.Append($@".{signature}"); //Signature
                return sb.ToString();
            }
            return signature;
        }

        public static bool Verify(this string input, string signatureKey) {
            if (string.IsNullOrWhiteSpace(input)) return false;
            //It should contain three parts.

            var inputArr = input.Split(".".ToCharArray());
            if (inputArr.Length != 3) throw new ArgumentException("Input not in desired format. Expects three components");
            var header = inputArr[0].Trim();

            header = header.DeSanitizeBase64();
            header = Encoding.UTF8.GetString(Convert.FromBase64String(header)); //Get the string of the header.
            var headerJN = JsonNode.Parse(header);
            Enum.TryParse<HashMethod>(headerJN["alg"].GetValue<string>(),out var method);

            var payload = inputArr[1].Trim();
            var signature = inputArr[2].Trim();

            var otherComp = string.Join(".", inputArr.Take(inputArr.Length - 1)); //Take first two only.

            var genSign = HashUtils.ComputeSignature(otherComp, signatureKey, method);
            genSign = genSign.SanitizeBase64();
            return signature == genSign;
        }
        #endregion
    }
}
