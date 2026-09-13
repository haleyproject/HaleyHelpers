using Haley.Models;
using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Haley.Utils
{
    public static partial class EncryptionUtils
    {
        public static partial class ASymmetric
        {
            public static class Envelope
            {
                private const string ResourcePrefix = "Haley.Resources.RsaKeys.";
                private const string RsaObjectIdentifier = "1.2.840.113549.1.1.1";
                private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);
                private static readonly IReadOnlyList<string> KnownKeys = Array.AsReadOnly(new[]
                {
                    RsaKeyNames.Default,
                    RsaKeyNames.Kida,
                    RsaKeyNames.Felina
                });

                public static string Prepare(string content, string privateKey, string key = RsaKeyNames.Default)
                {
                    if (content == null)
                    {
                        throw new ArgumentNullException(nameof(content));
                    }

                    var normalizedContent = content.Trim();
                    if (normalizedContent.Length == 0)
                    {
                        throw new ArgumentException("RSA envelope content cannot be empty.", nameof(content));
                    }

                    if (!IsValidKeyName(key))
                    {
                        throw new ArgumentException("The key name may contain only lowercase letters, digits, dots, and hyphens.", nameof(key));
                    }

                    var payload = StrictUtf8.GetBytes(normalizedContent);
                    byte[] signature;
                    using (var rsa = ReadPrivateKey(privateKey))
                    {
                        signature = rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                        if (!rsa.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
                        {
                            throw new CryptographicException("The generated RSA signature could not be validated.");
                        }
                    }

                    var envelope = new RsaEnvelope
                    {
                        Payload = Convert.ToBase64String(payload).SanitizeBase64(),
                        Signature = Convert.ToBase64String(signature).SanitizeBase64(),
                        Key = key
                    };

                    var serialized = JsonSerializer.Serialize(envelope);
                    if (TryGetPublicKey(key, out var registeredPublicKey))
                    {
                        var validation = Validate(serialized, registeredPublicKey);
                        if (!validation.IsValid)
                        {
                            throw new CryptographicException("The private key does not match Haley's registered public key '" + key + "'.");
                        }
                    }

                    return serialized;
                }

                public static RsaVerificationResult Validate(string envelope)
                {
                    return Validate(envelope, null);
                }

                public static RsaVerificationResult Validate(string envelope, string? publicKey)
                {
                    RsaEnvelope? parsed = null;
                    try
                    {
                        if (string.IsNullOrWhiteSpace(envelope))
                        {
                            return RsaVerificationResult.Invalid(null, "rsa.empty");
                        }

                        parsed = JsonSerializer.Deserialize<RsaEnvelope>(envelope);
                        if (parsed == null
                            || string.IsNullOrWhiteSpace(parsed.Payload)
                            || string.IsNullOrWhiteSpace(parsed.Signature)
                            || !IsValidKeyName(parsed.Key))
                        {
                            return RsaVerificationResult.Invalid(parsed?.Key, "rsa.invalid_envelope");
                        }

                        if (string.IsNullOrWhiteSpace(publicKey)
                            && !TryGetPublicKey(parsed.Key, out publicKey))
                        {
                            return RsaVerificationResult.Invalid(parsed.Key, "rsa.unknown_key");
                        }

                        var payload = parsed.Payload.SafeBase64Decode();
                        var signature = parsed.Signature.SafeBase64Decode();
                        bool isValid;
                        using (var rsa = ReadPublicKey(publicKey!))
                        {
                            isValid = rsa.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                        }

                        if (!isValid)
                        {
                            return RsaVerificationResult.Invalid(parsed.Key, "rsa.invalid_signature");
                        }

                        return RsaVerificationResult.Valid(parsed.Key, StrictUtf8.GetString(payload));
                    }
                    catch (JsonException)
                    {
                        return RsaVerificationResult.Invalid(parsed?.Key, "rsa.invalid_json");
                    }
                    catch (DecoderFallbackException)
                    {
                        return RsaVerificationResult.Invalid(parsed?.Key, "rsa.invalid_payload_encoding");
                    }
                    catch (FormatException)
                    {
                        return RsaVerificationResult.Invalid(parsed?.Key, "rsa.invalid_encoding");
                    }
                    catch (AsnContentException)
                    {
                        return RsaVerificationResult.Invalid(parsed?.Key, "rsa.invalid_key");
                    }
                    catch (CryptographicException)
                    {
                        return RsaVerificationResult.Invalid(parsed?.Key, "rsa.invalid_key_or_signature");
                    }
                    catch (ArgumentException)
                    {
                        return RsaVerificationResult.Invalid(parsed?.Key, "rsa.invalid_key_or_signature");
                    }
                }

                public static IReadOnlyList<string> GetKnownKeys()
                {
                    return KnownKeys;
                }

                public static string GetPublicKey(string key)
                {
                    if (!TryGetPublicKey(key, out var publicKey))
                    {
                        throw new KeyNotFoundException("No trusted RSA public key is registered as '" + key + "'.");
                    }

                    return publicKey!;
                }

                public static bool TryGetPublicKey(string key, out string? publicKey)
                {
                    publicKey = null;
                    if (!IsValidKeyName(key) || !ContainsKnownKey(key))
                    {
                        return false;
                    }

                    var resourceName = ResourcePrefix + key + ".pubkey";
                    var bytes = ResourceUtils.GetEmbeddedResource(resourceName, typeof(EncryptionUtils).GetTypeInfo().Assembly);
                    if (bytes == null || bytes.Length == 0)
                    {
                        return false;
                    }

                    publicKey = Encoding.UTF8.GetString(bytes).Trim();
                    return true;
                }

                public static bool IsValidKeyName(string key)
                {
                    if (string.IsNullOrWhiteSpace(key) || key.Length > 64)
                    {
                        return false;
                    }

                    for (var index = 0; index < key.Length; index++)
                    {
                        var character = key[index];
                        var allowed = character >= 'a' && character <= 'z'
                            || character >= '0' && character <= '9'
                            || character == '.'
                            || character == '-';
                        if (!allowed)
                        {
                            return false;
                        }
                    }

                    return true;
                }

                private static bool ContainsKnownKey(string key)
                {
                    for (var index = 0; index < KnownKeys.Count; index++)
                    {
                        if (string.Equals(KnownKeys[index], key, StringComparison.Ordinal))
                        {
                            return true;
                        }
                    }

                    return false;
                }

                private static RSA ReadPrivateKey(string keyMaterial)
                {
                    var material = EnsureMaterial(keyMaterial);
                    if (material.StartsWith("<RSAKeyValue", StringComparison.Ordinal))
                    {
                        var xmlRsa = RSA.Create();
                        xmlRsa.FromXmlString(material);
                        return xmlRsa;
                    }

                    var pem = DecodePem(material);
                    var parameters = pem.Label == "RSA PRIVATE KEY"
                        ? ReadPkcs1PrivateKey(pem.Bytes)
                        : pem.Label == "PRIVATE KEY"
                            ? ReadPkcs8PrivateKey(pem.Bytes)
                            : ReadPrivateKeyWithoutLabel(pem.Bytes);

                    var rsa = RSA.Create();
                    rsa.ImportParameters(parameters);
                    return rsa;
                }

                private static RSA ReadPublicKey(string keyMaterial)
                {
                    var material = EnsureMaterial(keyMaterial);
                    if (material.StartsWith("<RSAKeyValue", StringComparison.Ordinal))
                    {
                        var xmlRsa = RSA.Create();
                        xmlRsa.FromXmlString(material);
                        return xmlRsa;
                    }

                    var pem = DecodePem(material);
                    var parameters = pem.Label == "RSA PUBLIC KEY"
                        ? ReadPkcs1PublicKey(pem.Bytes)
                        : pem.Label == "PUBLIC KEY"
                            ? ReadSubjectPublicKeyInfo(pem.Bytes)
                            : ReadPublicKeyWithoutLabel(pem.Bytes);

                    var rsa = RSA.Create();
                    rsa.ImportParameters(parameters);
                    return rsa;
                }

                private static string EnsureMaterial(string keyMaterial)
                {
                    if (string.IsNullOrWhiteSpace(keyMaterial))
                    {
                        throw new ArgumentException("RSA key material is required.", nameof(keyMaterial));
                    }

                    return keyMaterial.Trim();
                }

                private static (string Label, byte[] Bytes) DecodePem(string material)
                {
                    if (!material.StartsWith("-----BEGIN ", StringComparison.Ordinal))
                    {
                        return (string.Empty, material.SafeBase64Decode());
                    }

                    var firstBreak = material.IndexOf('\n');
                    if (firstBreak < 0)
                    {
                        throw new FormatException("The PEM key does not contain a body.");
                    }

                    var header = material.Substring(0, firstBreak).TrimEnd('\r');
                    var label = header.Substring("-----BEGIN ".Length);
                    if (!label.EndsWith("-----", StringComparison.Ordinal))
                    {
                        throw new FormatException("The PEM key header is invalid.");
                    }

                    label = label.Substring(0, label.Length - 5);
                    var footer = "-----END " + label + "-----";
                    var footerIndex = material.IndexOf(footer, firstBreak, StringComparison.Ordinal);
                    if (footerIndex < 0)
                    {
                        throw new FormatException("The PEM key footer is missing.");
                    }

                    var body = material.Substring(firstBreak + 1, footerIndex - firstBreak - 1);
                    return (label, body.SafeBase64Decode());
                }

                private static RSAParameters ReadPrivateKeyWithoutLabel(byte[] bytes)
                {
                    try
                    {
                        return ReadPkcs8PrivateKey(bytes);
                    }
                    catch (Exception)
                    {
                        return ReadPkcs1PrivateKey(bytes);
                    }
                }

                private static RSAParameters ReadPublicKeyWithoutLabel(byte[] bytes)
                {
                    try
                    {
                        return ReadSubjectPublicKeyInfo(bytes);
                    }
                    catch (Exception)
                    {
                        return ReadPkcs1PublicKey(bytes);
                    }
                }

                private static RSAParameters ReadPkcs8PrivateKey(byte[] bytes)
                {
                    var reader = new AsnReader(bytes, AsnEncodingRules.DER);
                    var sequence = reader.ReadSequence();
                    sequence.ReadIntegerBytes();
                    ReadRsaAlgorithm(sequence.ReadSequence());
                    var privateKey = sequence.ReadOctetString();
                    sequence.ThrowIfNotEmpty();
                    reader.ThrowIfNotEmpty();
                    return ReadPkcs1PrivateKey(privateKey);
                }

                private static RSAParameters ReadPkcs1PrivateKey(byte[] bytes)
                {
                    var reader = new AsnReader(bytes, AsnEncodingRules.DER);
                    var sequence = reader.ReadSequence();
                    sequence.ReadIntegerBytes();
                    var parameters = new RSAParameters
                    {
                        Modulus = ReadUnsignedInteger(sequence),
                        Exponent = ReadUnsignedInteger(sequence),
                        D = ReadUnsignedInteger(sequence),
                        P = ReadUnsignedInteger(sequence),
                        Q = ReadUnsignedInteger(sequence),
                        DP = ReadUnsignedInteger(sequence),
                        DQ = ReadUnsignedInteger(sequence),
                        InverseQ = ReadUnsignedInteger(sequence)
                    };
                    sequence.ThrowIfNotEmpty();
                    reader.ThrowIfNotEmpty();
                    return NormalizePrivateParameters(parameters);
                }

                private static RSAParameters NormalizePrivateParameters(RSAParameters parameters)
                {
                    var modulusLength = parameters.Modulus?.Length
                        ?? throw new FormatException("The RSA private key does not contain a modulus.");
                    var factorLength = (modulusLength + 1) / 2;
                    parameters.D = PadUnsignedInteger(parameters.D, modulusLength);
                    parameters.P = PadUnsignedInteger(parameters.P, factorLength);
                    parameters.Q = PadUnsignedInteger(parameters.Q, factorLength);
                    parameters.DP = PadUnsignedInteger(parameters.DP, factorLength);
                    parameters.DQ = PadUnsignedInteger(parameters.DQ, factorLength);
                    parameters.InverseQ = PadUnsignedInteger(parameters.InverseQ, factorLength);
                    return parameters;
                }

                private static byte[] PadUnsignedInteger(byte[]? value, int length)
                {
                    if (value == null || value.Length == 0 || value.Length > length)
                    {
                        throw new FormatException("The RSA private key contains an invalid integer.");
                    }

                    if (value.Length == length)
                    {
                        return value;
                    }

                    var padded = new byte[length];
                    Buffer.BlockCopy(value, 0, padded, length - value.Length, value.Length);
                    return padded;
                }

                private static RSAParameters ReadSubjectPublicKeyInfo(byte[] bytes)
                {
                    var reader = new AsnReader(bytes, AsnEncodingRules.DER);
                    var sequence = reader.ReadSequence();
                    ReadRsaAlgorithm(sequence.ReadSequence());
                    var publicKey = sequence.ReadBitString(out var unusedBitCount);
                    if (unusedBitCount != 0)
                    {
                        throw new FormatException("The RSA public key contains unused bits.");
                    }

                    sequence.ThrowIfNotEmpty();
                    reader.ThrowIfNotEmpty();
                    return ReadPkcs1PublicKey(publicKey.ToArray());
                }

                private static RSAParameters ReadPkcs1PublicKey(byte[] bytes)
                {
                    var reader = new AsnReader(bytes, AsnEncodingRules.DER);
                    var sequence = reader.ReadSequence();
                    var parameters = new RSAParameters
                    {
                        Modulus = ReadUnsignedInteger(sequence),
                        Exponent = ReadUnsignedInteger(sequence)
                    };
                    sequence.ThrowIfNotEmpty();
                    reader.ThrowIfNotEmpty();
                    return parameters;
                }

                private static void ReadRsaAlgorithm(AsnReader algorithm)
                {
                    var identifier = algorithm.ReadObjectIdentifier();
                    if (!string.Equals(identifier, RsaObjectIdentifier, StringComparison.Ordinal))
                    {
                        throw new FormatException("The supplied key is not an RSA key.");
                    }

                    if (algorithm.HasData)
                    {
                        algorithm.ReadNull();
                    }

                    algorithm.ThrowIfNotEmpty();
                }

                private static byte[] ReadUnsignedInteger(AsnReader reader)
                {
                    var value = reader.ReadIntegerBytes().ToArray();
                    var offset = 0;
                    while (offset < value.Length - 1 && value[offset] == 0)
                    {
                        offset++;
                    }

                    if (offset == 0)
                    {
                        return value;
                    }

                    var normalized = new byte[value.Length - offset];
                    Buffer.BlockCopy(value, offset, normalized, 0, normalized.Length);
                    return normalized;
                }
            }
        }
    }
}
