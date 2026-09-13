using Haley.Models;
using System;
using System.Formats.Asn1;
using System.Security.Cryptography;

namespace Haley.Utils
{
    public static partial class EncryptionUtils
    {
        public static partial class ASymmetric
        {
            public static RsaKeyPair CreatePemKeyPair(int keySize = 3072)
            {
                if (keySize < 2048 || keySize > 8192 || keySize % 256 != 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(keySize), "RSA key size must be between 2048 and 8192 bits in 256-bit increments.");
                }

                using (var rsa = RSA.Create())
                {
                    rsa.KeySize = keySize;
                    var parameters = rsa.ExportParameters(true);
                    return new RsaKeyPair
                    {
                        PrivateKey = EncodePem("PRIVATE KEY", EncodePkcs8(parameters)),
                        PublicKey = EncodePem("PUBLIC KEY", EncodeSubjectPublicKeyInfo(parameters))
                    };
                }
            }

            public static string DerivePemPublicKey(string privateKey)
            {
                if (string.IsNullOrWhiteSpace(privateKey))
                {
                    throw new ArgumentException("RSA private key material is required.", nameof(privateKey));
                }

                var probe = Envelope.Prepare("haley.rsa.public-key.probe", privateKey, "deployment");
                _ = probe;

                var parameters = ReadPrivateParameters(privateKey);
                return EncodePem("PUBLIC KEY", EncodeSubjectPublicKeyInfo(parameters));
            }

            private static RSAParameters ReadPrivateParameters(string privateKey)
            {
                var normalized = privateKey.Trim();
                if (!normalized.StartsWith("-----BEGIN PRIVATE KEY-----", StringComparison.Ordinal))
                {
                    throw new ArgumentException("Only PKCS#8 PEM private keys can be used to derive a public key.", nameof(privateKey));
                }

                var start = normalized.IndexOf('\n');
                var end = normalized.IndexOf("-----END PRIVATE KEY-----", StringComparison.Ordinal);
                if (start < 0 || end <= start)
                {
                    throw new FormatException("The PKCS#8 PEM private key is malformed.");
                }

                var body = normalized.Substring(start + 1, end - start - 1).Replace("\r", string.Empty).Replace("\n", string.Empty);
                var bytes = Convert.FromBase64String(body);
                var reader = new AsnReader(bytes, AsnEncodingRules.DER);
                var sequence = reader.ReadSequence();
                sequence.ReadInteger();
                var algorithm = sequence.ReadSequence();
                algorithm.ReadObjectIdentifier();
                if (algorithm.HasData) algorithm.ReadNull();
                algorithm.ThrowIfNotEmpty();
                var privateBytes = sequence.ReadOctetString();
                sequence.ThrowIfNotEmpty();
                reader.ThrowIfNotEmpty();

                var privateReader = new AsnReader(privateBytes, AsnEncodingRules.DER);
                var privateSequence = privateReader.ReadSequence();
                privateSequence.ReadInteger();
                var result = new RSAParameters
                {
                    Modulus = ReadUnsigned(privateSequence),
                    Exponent = ReadUnsigned(privateSequence),
                    D = ReadUnsigned(privateSequence),
                    P = ReadUnsigned(privateSequence),
                    Q = ReadUnsigned(privateSequence),
                    DP = ReadUnsigned(privateSequence),
                    DQ = ReadUnsigned(privateSequence),
                    InverseQ = ReadUnsigned(privateSequence)
                };
                privateSequence.ThrowIfNotEmpty();
                privateReader.ThrowIfNotEmpty();
                return result;
            }

            private static byte[] EncodePkcs8(RSAParameters parameters)
            {
                var privateWriter = new AsnWriter(AsnEncodingRules.DER);
                privateWriter.PushSequence();
                privateWriter.WriteInteger(0);
                WriteUnsigned(privateWriter, parameters.Modulus);
                WriteUnsigned(privateWriter, parameters.Exponent);
                WriteUnsigned(privateWriter, parameters.D);
                WriteUnsigned(privateWriter, parameters.P);
                WriteUnsigned(privateWriter, parameters.Q);
                WriteUnsigned(privateWriter, parameters.DP);
                WriteUnsigned(privateWriter, parameters.DQ);
                WriteUnsigned(privateWriter, parameters.InverseQ);
                privateWriter.PopSequence();

                var writer = new AsnWriter(AsnEncodingRules.DER);
                writer.PushSequence();
                writer.WriteInteger(0);
                writer.PushSequence();
                writer.WriteObjectIdentifier("1.2.840.113549.1.1.1");
                writer.WriteNull();
                writer.PopSequence();
                writer.WriteOctetString(privateWriter.Encode());
                writer.PopSequence();
                return writer.Encode();
            }

            private static byte[] EncodeSubjectPublicKeyInfo(RSAParameters parameters)
            {
                var publicWriter = new AsnWriter(AsnEncodingRules.DER);
                publicWriter.PushSequence();
                WriteUnsigned(publicWriter, parameters.Modulus);
                WriteUnsigned(publicWriter, parameters.Exponent);
                publicWriter.PopSequence();

                var writer = new AsnWriter(AsnEncodingRules.DER);
                writer.PushSequence();
                writer.PushSequence();
                writer.WriteObjectIdentifier("1.2.840.113549.1.1.1");
                writer.WriteNull();
                writer.PopSequence();
                writer.WriteBitString(publicWriter.Encode());
                writer.PopSequence();
                return writer.Encode();
            }

            private static void WriteUnsigned(AsnWriter writer, byte[]? value)
            {
                if (value == null || value.Length == 0)
                {
                    throw new CryptographicException("The RSA key is missing a required parameter.");
                }

                var offset = 0;
                while (offset < value.Length - 1 && value[offset] == 0) offset++;
                writer.WriteIntegerUnsigned(new ReadOnlySpan<byte>(value, offset, value.Length - offset));
            }

            private static byte[] ReadUnsigned(AsnReader reader)
            {
                var bytes = reader.ReadIntegerBytes().ToArray();
                var offset = 0;
                while (offset < bytes.Length - 1 && bytes[offset] == 0) offset++;
                if (offset == 0) return bytes;
                var result = new byte[bytes.Length - offset];
                Buffer.BlockCopy(bytes, offset, result, 0, result.Length);
                return result;
            }

            private static string EncodePem(string label, byte[] bytes)
            {
                var base64 = Convert.ToBase64String(bytes);
                var builder = new System.Text.StringBuilder();
                builder.Append("-----BEGIN ").Append(label).AppendLine("-----");
                for (var index = 0; index < base64.Length; index += 64)
                {
                    builder.AppendLine(base64.Substring(index, Math.Min(64, base64.Length - index)));
                }
                builder.Append("-----END ").Append(label).Append("-----");
                return builder.ToString();
            }
        }
    }
}
