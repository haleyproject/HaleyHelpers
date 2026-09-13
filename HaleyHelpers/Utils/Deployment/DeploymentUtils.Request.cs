using Haley.Internal;
using Haley.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace Haley.Utils
{
    public static partial class DeploymentUtils
    {
        internal const int SupportedVersion = 1;
        internal const int MaxArtifactBytes = 256 * 1024;
        internal const string DeployDirectoryName = "deployinfo";
        internal const string PrivateKeyFileName = "deploy.pem";
        internal const string PublicKeyFileName = "deploy.pub";
        internal const string RequestFileName = "request.json";
        internal const string RecoveryFileName = "recovery.json";
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);
        private static readonly object FileGate = new object();

        public static DeploymentRequestResult PrepareRequest(DeploymentRequestInput input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            try
            {
                var normalized = NormalizeInput(input);
                lock (FileGate)
                {
                    var root = GetDeploymentDirectory(normalized.BaseDirectory);
                    Directory.CreateDirectory(root);
                    var privatePath = Path.Combine(root, PrivateKeyFileName);
                    var publicPath = Path.Combine(root, PublicKeyFileName);
                    var requestPath = Path.Combine(root, RequestFileName);
                    var privateExists = File.Exists(privatePath);
                    var publicExists = File.Exists(publicPath);
                    var generated = false;

                    if (!privateExists && !publicExists)
                    {
                        var pair = EncryptionUtils.ASymmetric.CreatePemKeyPair();
                        WriteAtomically(privatePath, pair.PrivateKey, overwrite: false);
                        WriteAtomically(publicPath, pair.PublicKey, overwrite: false);
                        privateExists = publicExists = generated = true;
                    }
                    else if (privateExists && !publicExists)
                    {
                        var restored = EncryptionUtils.ASymmetric.DerivePemPublicKey(ReadBoundedText(privatePath));
                        WriteAtomically(publicPath, restored, overwrite: false);
                        publicExists = true;
                    }

                    if (!publicExists)
                    {
                        return RequestFailure("request.public_key_missing", requestPath);
                    }

                    DeploymentRequest? previous = null;
                    string? previousEnvelope = null;
                    if (File.Exists(requestPath))
                    {
                        previousEnvelope = ReadBoundedText(requestPath);
                        var existing = ValidateRequestEnvelope(previousEnvelope, ReadBoundedText(publicPath));
                        if (!existing.IsValid || existing.Request == null)
                        {
                            existing.RequestPath = requestPath;
                            return existing;
                        }
                        previous = existing.Request;
                        if (!string.Equals(previous.Product, normalized.Product, StringComparison.Ordinal)
                            || !string.Equals(previous.Deployment, normalized.Deployment, StringComparison.Ordinal))
                        {
                            return RequestFailure("request.identity_conflict", requestPath);
                        }
                    }
                    else if (!generated)
                    {
                        return RequestFailure("request.missing_for_existing_deployment", requestPath);
                    }

                    if (!privateExists)
                    {
                        return previous == null
                            ? RequestFailure("request.private_key_missing", requestPath)
                            : new DeploymentRequestResult
                            {
                                IsValid = true,
                                Error = "request.private_key_missing_update_skipped",
                                Envelope = previousEnvelope,
                                Request = previous,
                                RequestPath = requestPath
                            };
                    }

                    var evidence = BuildRequestEvidence(normalized.MachineEvidenceMode);
                    if (normalized.MachineEvidenceMode == MachineLockMode.Lite && evidence.Lite.Count < 1)
                    {
                        return RequestFailure("request.lite_machine_evidence_unavailable", requestPath);
                    }
                    if (normalized.MachineEvidenceMode == MachineLockMode.Strong && evidence.Strong.Count < 2)
                    {
                        return RequestFailure("request.strong_machine_evidence_unavailable", requestPath);
                    }

                    var request = new DeploymentRequest
                    {
                        Version = SupportedVersion,
                        DeployId = previous?.DeployId ?? Guid.NewGuid().ToString("N"),
                        Created = previous?.Created ?? normalized.NowUtc!.Value,
                        Deployment = normalized.Deployment,
                        Product = normalized.Product,
                        ProductVersion = normalized.ProductVersion,
                        Features = NormalizeCatalog(normalized.Features),
                        AvailableLimits = NormalizeCatalog(normalized.AvailableLimits),
                        MachineEvidence = evidence
                    };
                    var encodedRequest = JsonSerializer.Serialize(request, DeploymentJson.CompactOptions);
                    if (previous != null
                        && previousEnvelope != null
                        && string.Equals(
                            JsonSerializer.Serialize(previous, DeploymentJson.CompactOptions),
                            encodedRequest,
                            StringComparison.Ordinal))
                    {
                        return new DeploymentRequestResult
                        {
                            IsValid = true,
                            Envelope = previousEnvelope,
                            Request = previous,
                            RequestPath = requestPath
                        };
                    }

                    var proofEnvelope = EncryptionUtils.ASymmetric.Envelope.Prepare(
                        DeploymentRequestCanonicalizer.Create(request), ReadBoundedText(privatePath), "deployment");
                    var proof = JsonSerializer.Deserialize<RsaEnvelope>(proofEnvelope, DeploymentJson.CompactOptions)
                        ?? throw new InvalidOperationException("The deployment proof could not be prepared.");
                    var envelope = new RequestEnvelope
                    {
                        Request = Convert.ToBase64String(StrictUtf8.GetBytes(encodedRequest)).SanitizeBase64(),
                        DeployPrint = proof.Signature
                    };
                    var serialized = JsonSerializer.Serialize(envelope, DeploymentJson.Options);
                    var validation = ValidateRequestEnvelope(serialized, ReadBoundedText(publicPath));
                    if (!validation.IsValid)
                    {
                        return validation;
                    }

                    WriteAtomically(requestPath, serialized, overwrite: true);
                    validation.Envelope = serialized;
                    validation.RequestPath = requestPath;
                    return validation;
                }
            }
            catch (Exception exception) when (IsExpectedFailure(exception))
            {
                return RequestFailure("request.prepare_failed", null, exception.Message);
            }
        }

        public static DeploymentRequestResult DecodeRequestEnvelope(string envelope)
        {
            try
            {
                var parsed = ParseEnvelope(envelope);
                var request = ParseRequest(parsed.Request);
                var structuralError = ValidateRequestStructure(request);
                return structuralError == null
                    ? new DeploymentRequestResult { IsValid = true, Envelope = envelope, Request = request }
                    : RequestFailure(structuralError, null);
            }
            catch (Exception exception) when (IsExpectedFailure(exception))
            {
                return RequestFailure("request.invalid", null);
            }
        }

        public static DeploymentRequestResult ValidateRequestEnvelope(string envelope, string publicKey)
        {
            var decoded = DecodeRequestEnvelope(envelope);
            if (!decoded.IsValid || decoded.Request == null) return decoded;
            try
            {
                var parsed = ParseEnvelope(envelope);
                return ValidateDeployPrint(decoded.Request, parsed.DeployPrint, publicKey)
                    ? decoded
                    : RequestFailure("request.invalid_deploy_print", null);
            }
            catch (Exception exception) when (IsExpectedFailure(exception))
            {
                return RequestFailure("request.invalid_deploy_print", null);
            }
        }

        internal static bool ValidateDeployPrint(DeploymentRequest request, string deployPrint, string publicKey)
        {
            var canonical = DeploymentRequestCanonicalizer.Create(request).Trim();
            var proof = new RsaEnvelope
            {
                Payload = Convert.ToBase64String(StrictUtf8.GetBytes(canonical)).SanitizeBase64(),
                Signature = deployPrint,
                Key = "deployment"
            };
            var proofJson = JsonSerializer.Serialize(proof, DeploymentJson.CompactOptions);
            return EncryptionUtils.ASymmetric.Envelope.Validate(proofJson, publicKey).IsValid;
        }

        internal static DeploymentRequestInput NormalizeInput(DeploymentRequestInput input)
        {
            if (!Enum.IsDefined(typeof(MachineLockMode), input.MachineEvidenceMode))
                throw new ArgumentOutOfRangeException(nameof(input.MachineEvidenceMode));
            var product = NormalizeCode(input.Product, nameof(input.Product));
            var deployment = NormalizeCode(input.Deployment, nameof(input.Deployment));
            var version = NormalizeText(input.ProductVersion, nameof(input.ProductVersion), 64);
            return new DeploymentRequestInput
            {
                Product = product,
                ProductVersion = version,
                Deployment = deployment,
                Features = input.Features ?? Array.Empty<string>(),
                AvailableLimits = input.AvailableLimits ?? Array.Empty<string>(),
                MachineEvidenceMode = input.MachineEvidenceMode,
                BaseDirectory = input.BaseDirectory,
                NowUtc = (input.NowUtc ?? DateTimeOffset.UtcNow).ToUniversalTime()
            };
        }

        internal static string GetDeploymentDirectory(string? baseDirectory)
        {
            var root = string.IsNullOrWhiteSpace(baseDirectory) ? AppContext.BaseDirectory : baseDirectory.Trim();
            return Path.Combine(Path.GetFullPath(root), DeployDirectoryName);
        }

        internal static string ReadBoundedText(string path)
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length <= 0 || info.Length > MaxArtifactBytes)
                throw new InvalidDataException("Deployment artifact is missing, empty, or exceeds 256 KB.");
            return StrictUtf8.GetString(File.ReadAllBytes(path));
        }

        internal static void WriteAtomically(string path, string value, bool overwrite)
        {
            var directory = Path.GetDirectoryName(path) ?? throw new InvalidOperationException("The target path has no directory.");
            Directory.CreateDirectory(directory);
            if (!overwrite && File.Exists(path)) throw new IOException("The target already exists.");
            var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                File.WriteAllText(temporary, value, new UTF8Encoding(false));
                if (File.Exists(path)) File.Replace(temporary, path, null);
                else File.Move(temporary, path);
            }
            finally
            {
                if (File.Exists(temporary)) File.Delete(temporary);
            }
        }

        internal static bool IsExpectedFailure(Exception exception)
        {
            return exception is IOException
                || exception is UnauthorizedAccessException
                || exception is InvalidDataException
                || exception is InvalidOperationException
                || exception is ArgumentException
                || exception is JsonException
                || exception is FormatException
                || exception is System.Security.Cryptography.CryptographicException;
        }

        private static RequestEnvelope ParseEnvelope(string envelope)
        {
            if (string.IsNullOrWhiteSpace(envelope) || StrictUtf8.GetByteCount(envelope) > MaxArtifactBytes)
                throw new InvalidDataException("Request envelope is empty or too large.");
            var parsed = JsonSerializer.Deserialize<RequestEnvelope>(envelope, DeploymentJson.CompactOptions)
                ?? throw new InvalidDataException("Request envelope is empty.");
            if (string.IsNullOrWhiteSpace(parsed.Request) || string.IsNullOrWhiteSpace(parsed.DeployPrint))
                throw new InvalidDataException("Request envelope is incomplete.");
            return parsed;
        }

        private static DeploymentRequest ParseRequest(string request)
        {
            var bytes = request.SafeBase64Decode();
            if (bytes.Length == 0 || bytes.Length > MaxArtifactBytes)
                throw new InvalidDataException("Deployment request is empty or too large.");
            return JsonSerializer.Deserialize<DeploymentRequest>(StrictUtf8.GetString(bytes), DeploymentJson.CompactOptions)
                ?? throw new InvalidDataException("Deployment request is empty.");
        }

        private static string? ValidateRequestStructure(DeploymentRequest request)
        {
            if (request.Version != SupportedVersion) return "request.unsupported_version";
            if (!Guid.TryParseExact(request.DeployId, "N", out _)) return "request.invalid_deploy_id";
            if (request.Created == default) return "request.created_required";
            try
            {
                _ = NormalizeCode(request.Product, nameof(request.Product));
                _ = NormalizeCode(request.Deployment, nameof(request.Deployment));
                _ = NormalizeText(request.ProductVersion, nameof(request.ProductVersion), 64);
                request.Features = NormalizeCatalog(request.Features);
                request.AvailableLimits = NormalizeCatalog(request.AvailableLimits);
                ValidateEvidence(request.MachineEvidence);
            }
            catch (ArgumentException) { return "request.invalid_fields"; }
            return null;
        }

        private static void ValidateEvidence(MachineEvidence? evidence)
        {
            if (evidence == null) throw new ArgumentException("Machine evidence is required.");
            foreach (var item in evidence.Lite.Concat(evidence.Strong))
            {
                _ = NormalizeCode(item.Source, nameof(item.Source));
                if (string.IsNullOrWhiteSpace(item.Fingerprint) || item.Fingerprint.SafeBase64Decode().Length != 32)
                    throw new ArgumentException("Machine fingerprint is invalid.");
            }
        }

        private static MachineEvidence BuildRequestEvidence(MachineLockMode mode)
        {
            var evidence = new MachineEvidence();
            if (mode == MachineLockMode.None) return evidence;
            var lite = AssetUtils.GetMachineEvidence(MachineLockMode.Lite);
            if (lite.IsAvailable) evidence.Lite.AddRange(lite.Fingerprints);
            if (mode == MachineLockMode.Strong)
            {
                var strong = AssetUtils.GetMachineEvidence(MachineLockMode.Strong);
                if (strong.IsAvailable) evidence.Strong.AddRange(strong.Fingerprints);
            }
            return evidence;
        }

        private static List<string> NormalizeCatalog(IEnumerable<string>? values)
        {
            return (values ?? Array.Empty<string>())
                .Select(value => NormalizeCode(value, "catalog value"))
                .Distinct(StringComparer.Ordinal)
                .OrderBy(value => value, StringComparer.Ordinal)
                .ToList();
        }

        private static string NormalizeCode(string value, string parameter)
        {
            var normalized = NormalizeText(value, parameter, 128).ToLowerInvariant();
            if (!char.IsLetterOrDigit(normalized[0]) || !char.IsLetterOrDigit(normalized[normalized.Length - 1]))
                throw new ArgumentException("Machine codes must begin and end with a letter or digit.", parameter);
            if (normalized.Any(character => !(char.IsLetterOrDigit(character) || character == '.' || character == '_' || character == '-' || character == ':')))
                throw new ArgumentException("Machine codes contain unsupported characters.", parameter);
            return normalized;
        }

        private static string NormalizeText(string value, string parameter, int maximumLength)
        {
            if (string.IsNullOrWhiteSpace(value)) throw new ArgumentException("A value is required.", parameter);
            var normalized = value.Normalize(NormalizationForm.FormC).Trim();
            if (normalized.Length > maximumLength || normalized.Any(char.IsControl))
                throw new ArgumentException("The value is invalid or too long.", parameter);
            return normalized;
        }

        private static DeploymentRequestResult RequestFailure(string error, string? requestPath, string? message = null)
        {
            return new DeploymentRequestResult { IsValid = false, Error = error, Message = message, RequestPath = requestPath };
        }
    }
}
