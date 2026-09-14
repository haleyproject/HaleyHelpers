using Haley.Internal;
using Haley.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Haley.Utils
{
    public static partial class DeploymentUtils
    {
        internal const int SupportedVersion = 2;
        internal const int LegacyVersion = 1;
        internal const int MaxArtifactBytes = 256 * 1024;
        internal const string DeployDirectoryName = ".deployinfo";
        internal const string PrivateKeyFileName = "deploy.pem";
        internal const string PublicKeyFileName = "deploy.pub";
        internal const string LegacyRequestFileName = "request.json";
        internal const string IdentityFileName = "deployment.json";
        internal const string LicenseFileName = "license.lic";
        internal const string RecoveryFileName = "recovery.json";
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);
        private static readonly object FileGate = new object();

        public static DeploymentRequestResult PrepareRequest(DeploymentRequestInput input)
            => PrepareRequestCore(input, renew: false);

        public static DeploymentRequestResult RenewRequest(DeploymentRequestInput input)
            => PrepareRequestCore(input, renew: true);

        public static DeploymentRequestResult LoadRequest(DeploymentRequestInput input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            try
            {
                var normalized = NormalizeInput(input);
                lock (FileGate)
                {
                    var root = GetDeploymentDirectoryPath(normalized.BaseDirectory);
                    var requestPath = GetRequestPath(normalized.Product, normalized.BaseDirectory);
                    var publicPath = Path.Combine(root, PublicKeyFileName);
                    var identityPath = Path.Combine(root, IdentityFileName);
                    if (!File.Exists(publicPath)) return RequestFailure("request.public_key_missing", requestPath);
                    if (!File.Exists(identityPath)) return RequestFailure("request.identity_missing", requestPath);
                    if (!File.Exists(requestPath)) return RequestFailure("request.not_prepared", requestPath);

                    var publicKey = ReadBoundedText(publicPath);
                    var identity = ReadIdentity(identityPath, publicKey);
                    var result = ValidateRequestEnvelope(ReadBoundedText(requestPath), publicKey);
                    result.RequestPath = requestPath;
                    if (!result.IsValid || result.Request == null) return result;
                    if (result.Request.Version != SupportedVersion) return RequestFailure("request.renew_required", requestPath);
                    if (!string.Equals(result.Request.DeployId, identity.DeployId, StringComparison.Ordinal)
                        || !string.Equals(result.Request.Product, normalized.Product, StringComparison.Ordinal))
                    {
                        return RequestFailure("request.identity_conflict", requestPath);
                    }
                    return result;
                }
            }
            catch (Exception exception) when (IsExpectedFailure(exception))
            {
                return RequestFailure("request.load_failed", null, exception.Message);
            }
        }

        private static DeploymentRequestResult PrepareRequestCore(DeploymentRequestInput input, bool renew)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            try
            {
                var normalized = NormalizeInput(input);
                lock (FileGate)
                {
                    var root = GetDeploymentDirectoryPath(normalized.BaseDirectory);
                    var requestPath = GetRequestPath(normalized.Product, normalized.BaseDirectory);
                    var privatePath = Path.Combine(root, PrivateKeyFileName);
                    var publicPath = Path.Combine(root, PublicKeyFileName);
                    var identityPath = Path.Combine(root, IdentityFileName);
                    var legacyRequestPath = Path.Combine(root, LegacyRequestFileName);
                    var privateExists = File.Exists(privatePath);
                    var publicExists = File.Exists(publicPath);
                    var generated = false;

                    if (renew && !privateExists && !publicExists)
                        return RequestFailure("request.deployment_missing", requestPath);

                    Directory.CreateDirectory(root);
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

                    if (!publicExists) return RequestFailure("request.public_key_missing", requestPath);
                    var publicKey = ReadBoundedText(publicPath);
                    if (privateExists)
                    {
                        var derived = EncryptionUtils.ASymmetric.DerivePemPublicKey(ReadBoundedText(privatePath));
                        if (!string.Equals(ComputePublicKeyHash(derived), ComputePublicKeyHash(publicKey), StringComparison.Ordinal))
                            return RequestFailure("request.key_pair_mismatch", requestPath);
                    }

                    var identity = ResolveIdentity(identityPath, requestPath, legacyRequestPath, publicKey, generated, normalized.NowUtc!.Value);
                    if (identity == null) return RequestFailure("request.identity_missing", requestPath);

                    DeploymentRequestResult? existing = null;
                    if (File.Exists(requestPath))
                    {
                        existing = ValidateRequestEnvelope(ReadBoundedText(requestPath), publicKey);
                        existing.RequestPath = requestPath;
                        if (!existing.IsValid || existing.Request == null) return existing;
                        if (!string.Equals(existing.Request.DeployId, identity.DeployId, StringComparison.Ordinal)
                            || !string.Equals(existing.Request.Product, normalized.Product, StringComparison.Ordinal))
                        {
                            return RequestFailure("request.identity_conflict", requestPath);
                        }
                        if (!renew && RequestMatches(existing.Request, normalized)) return existing;
                        if (!renew) return RequestFailure("request.renew_required", requestPath);
                    }

                    if (!privateExists) return RequestFailure("request.private_key_missing", requestPath);

                    var request = new DeploymentRequest
                    {
                        Version = SupportedVersion,
                        DeployId = identity.DeployId,
                        Created = identity.Created,
                        Deployment = identity.DeployId,
                        Product = normalized.Product,
                        ProductVersion = normalized.ProductVersion,
                        Features = NormalizeCatalog(normalized.Features),
                        AvailableLimits = new List<string>(),
                        MachineEvidence = BuildRequestEvidence()
                    };
                    var encodedRequest = JsonSerializer.Serialize(request, DeploymentJson.CompactOptions);
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
                    var validation = ValidateRequestEnvelope(serialized, publicKey);
                    if (!validation.IsValid) return validation;

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
            var product = NormalizeCode(input.Product, nameof(input.Product));
            var version = NormalizeText(input.ProductVersion, nameof(input.ProductVersion), 64);
            return new DeploymentRequestInput
            {
                Product = product,
                ProductVersion = version,
                Features = input.Features ?? Array.Empty<string>(),
                BaseDirectory = input.BaseDirectory,
                NowUtc = (input.NowUtc ?? DateTimeOffset.UtcNow).ToUniversalTime()
            };
        }

        public static string GetDeploymentDirectoryPath(string? baseDirectory = null)
        {
            var root = string.IsNullOrWhiteSpace(baseDirectory) ? AppContext.BaseDirectory : baseDirectory!.Trim();
            return Path.Combine(Path.GetFullPath(root), DeployDirectoryName);
        }

        public static string GetRequestPath(string product, string? baseDirectory = null)
            => Path.Combine(GetDeploymentDirectoryPath(baseDirectory), NormalizeCode(product, nameof(product)) + ".request");

        public static string ResolveLicensePath(string? licensePath, string? baseDirectory = null)
        {
            var root = string.IsNullOrWhiteSpace(baseDirectory) ? AppContext.BaseDirectory : Path.GetFullPath(baseDirectory!.Trim());
            if (string.IsNullOrWhiteSpace(licensePath))
                return Path.Combine(GetDeploymentDirectoryPath(root), LicenseFileName);

            var configuredPath = licensePath!.Trim();
            return Path.GetFullPath(Path.IsPathRooted(configuredPath)
                ? configuredPath
                : Path.Combine(root, configuredPath));
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
            if (request.Version != SupportedVersion && request.Version != LegacyVersion) return "request.unsupported_version";
            if (!Guid.TryParseExact(request.DeployId, "N", out _)) return "request.invalid_deploy_id";
            if (request.Created == default) return "request.created_required";
            try
            {
                _ = NormalizeCode(request.Product, nameof(request.Product));
                if (request.Version == LegacyVersion) _ = NormalizeCode(request.Deployment, nameof(request.Deployment));
                if (request.Version == SupportedVersion && !string.Equals(request.Deployment, request.DeployId, StringComparison.Ordinal))
                    return "request.deployment_mismatch";
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

        private static MachineEvidence BuildRequestEvidence()
        {
            var evidence = new MachineEvidence();
            var lite = AssetUtils.GetMachineEvidence(MachineLockMode.Lite);
            if (lite.IsAvailable) evidence.Lite.AddRange(lite.Fingerprints);
            var strong = AssetUtils.GetMachineEvidence(MachineLockMode.Strong);
            if (strong.IsAvailable) evidence.Strong.AddRange(strong.Fingerprints);
            return evidence;
        }

        private static DeploymentIdentity? ResolveIdentity(
            string identityPath,
            string requestPath,
            string legacyRequestPath,
            string publicKey,
            bool generated,
            DateTimeOffset now)
        {
            if (File.Exists(identityPath)) return ReadIdentity(identityPath, publicKey);

            foreach (var candidate in new[] { requestPath, legacyRequestPath })
            {
                if (!File.Exists(candidate)) continue;
                var existing = ValidateRequestEnvelope(ReadBoundedText(candidate), publicKey);
                if (!existing.IsValid || existing.Request == null)
                    throw new InvalidDataException("The existing deployment request cannot establish the deployment identity.");
                var migrated = new DeploymentIdentity
                {
                    Version = 1,
                    DeployId = existing.Request.DeployId,
                    Created = existing.Request.Created,
                    PublicKeyHash = ComputePublicKeyHash(publicKey)
                };
                WriteAtomically(identityPath, JsonSerializer.Serialize(migrated, DeploymentJson.Options), overwrite: false);
                return migrated;
            }

            if (!generated) return null;
            var created = new DeploymentIdentity
            {
                Version = 1,
                DeployId = Guid.NewGuid().ToString("N"),
                Created = now,
                PublicKeyHash = ComputePublicKeyHash(publicKey)
            };
            WriteAtomically(identityPath, JsonSerializer.Serialize(created, DeploymentJson.Options), overwrite: false);
            return created;
        }

        private static DeploymentIdentity ReadIdentity(string path, string publicKey)
        {
            var identity = JsonSerializer.Deserialize<DeploymentIdentity>(ReadBoundedText(path), DeploymentJson.CompactOptions)
                ?? throw new InvalidDataException("The deployment identity is empty.");
            if (identity.Version != 1
                || !Guid.TryParseExact(identity.DeployId, "N", out _)
                || identity.Created == default
                || !string.Equals(identity.PublicKeyHash, ComputePublicKeyHash(publicKey), StringComparison.Ordinal))
            {
                throw new InvalidDataException("The deployment identity is invalid or does not belong to the deployment key.");
            }
            return identity;
        }

        private static string ComputePublicKeyHash(string publicKey)
        {
            var canonical = publicKey.Trim().Replace("\r\n", "\n");
            using (var sha = SHA256.Create())
            {
                return Convert.ToBase64String(sha.ComputeHash(StrictUtf8.GetBytes(canonical))).SanitizeBase64();
            }
        }

        private static bool RequestMatches(DeploymentRequest request, DeploymentRequestInput input)
        {
            return request.Version == SupportedVersion
                && string.Equals(request.ProductVersion, input.ProductVersion, StringComparison.Ordinal)
                && request.Features.SequenceEqual(NormalizeCatalog(input.Features), StringComparer.Ordinal);
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
