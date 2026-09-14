using Haley.Internal;
using Haley.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Haley.Utils
{
    public static partial class DeploymentUtils
    {
        internal const string FreeModeRequestFileName = "deploy.freemode.request";
        internal const string UnrestrictedOverrideFileName = "deploy.god.mode";
        private const int OverrideVersion = 1;
        private const string OverrideMode = "god";

        public static string PrepareUnrestrictedOverride(DeploymentOverrideInput input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (string.IsNullOrWhiteSpace(input.PrivateKey))
                throw new ArgumentException("The issuer private key is required.", nameof(input));
            if (!EncryptionUtils.ASymmetric.Envelope.IsValidKeyName(input.Key))
                throw new ArgumentException("The issuer key name is invalid.", nameof(input));

            var request = ParseOverrideRequest(input.Request);
            var error = ValidateOverrideStructure(request);
            if (error != null) throw new ArgumentException("The unrestricted deployment request is invalid (" + error + ").", nameof(input));
            var payload = JsonSerializer.Serialize(request, DeploymentJson.CompactOptions);
            return EncryptionUtils.ASymmetric.Envelope.Prepare(payload, input.PrivateKey, input.Key);
        }

        public static string GetFreeModeRequestPath(string? baseDirectory = null)
            => Path.Combine(GetDeploymentDirectoryPath(baseDirectory), FreeModeRequestFileName);

        public static string GetUnrestrictedOverridePath(string? baseDirectory = null)
            => Path.Combine(GetDeploymentDirectoryPath(baseDirectory), UnrestrictedOverrideFileName);

        private static DeploymentRequestResult WithFreeModeRequest(
            DeploymentRequestInput input,
            DeploymentRequestResult result)
        {
            if (!result.IsValid || result.Request == null) return result;
            try
            {
                var normalized = NormalizeInput(input);
                lock (FileGate)
                {
                    var publicPath = Path.Combine(GetDeploymentDirectoryPath(normalized.BaseDirectory), PublicKeyFileName);
                    var publicKey = ReadBoundedText(publicPath);
                    var request = new DeploymentOverrideRequest
                    {
                        Version = OverrideVersion,
                        Mode = OverrideMode,
                        DeployId = result.Request.DeployId,
                        Product = result.Request.Product
                    };
                    request.Fingerprint = ComputeOverrideFingerprint(request, publicKey);
                    var serialized = JsonSerializer.Serialize(request, DeploymentJson.Options);
                    var path = GetFreeModeRequestPath(normalized.BaseDirectory);
                    if (!File.Exists(path) || !string.Equals(ReadBoundedText(path), serialized, StringComparison.Ordinal))
                        WriteAtomically(path, serialized, overwrite: true);
                    result.OverrideRequestPath = path;
                    return result;
                }
            }
            catch (Exception exception) when (IsExpectedFailure(exception))
            {
                return RequestFailure("request.override_prepare_failed", result.RequestPath, exception.Message);
            }
        }

        private static DeploymentGrantResult? EvaluateUnrestrictedOverride(
            DeploymentGrantOptions options,
            string baseDirectory,
            DeploymentRequest localRequest,
            DateTimeOffset now)
        {
            var path = GetUnrestrictedOverridePath(baseDirectory);
            if (!File.Exists(path)) return null;

            try
            {
                var artifact = ReadBoundedText(path);
                var verification = ValidateIssuerEnvelope(artifact, options.PublicKeyPath, baseDirectory);
                if (!verification.IsValid || string.IsNullOrWhiteSpace(verification.Payload))
                    return OverrideResult(DeploymentGrantState.TamperedGrant, now,
                        verification.Error ?? "override.invalid_signature", path, localRequest, verification.Key);

                var request = ParseOverrideRequest(verification.Payload!);
                var error = ValidateOverrideStructure(request);
                if (error != null)
                    return OverrideResult(DeploymentGrantState.InvalidGrant, now, error, path, localRequest, verification.Key, request);
                if (!string.Equals(request.Product, options.Product, StringComparison.Ordinal))
                    return OverrideResult(DeploymentGrantState.InvalidGrant, now, "override.product_mismatch", path, localRequest, verification.Key, request);
                if (!string.Equals(request.DeployId, localRequest.DeployId, StringComparison.Ordinal))
                    return OverrideResult(DeploymentGrantState.InvalidDeployment, now, "override.deployment_mismatch", path, localRequest, verification.Key, request);

                var publicPath = Path.Combine(GetDeploymentDirectoryPath(baseDirectory), PublicKeyFileName);
                var publicKey = ReadBoundedText(publicPath);
                if (!string.Equals(request.Fingerprint, ComputeOverrideFingerprint(request, publicKey), StringComparison.Ordinal))
                    return OverrideResult(DeploymentGrantState.InvalidDeployment, now, "override.fingerprint_mismatch", path, localRequest, verification.Key, request);

                return OverrideResult(
                    DeploymentGrantState.Unrestricted,
                    now,
                    null,
                    path,
                    localRequest,
                    verification.Key,
                    request,
                    KnownFeatures(options.Features, enabled: true));
            }
            catch (Exception exception) when (IsExpectedFailure(exception))
            {
                return OverrideResult(DeploymentGrantState.InvalidGrant, now,
                    "override.artifact_invalid", path, localRequest, message: exception.Message);
            }
        }

        private static DeploymentGrantResult OverrideResult(
            DeploymentGrantState state,
            DateTimeOffset now,
            string? error,
            string path,
            DeploymentRequest request,
            string? key = null,
            DeploymentOverrideRequest? deploymentOverride = null,
            IReadOnlyDictionary<string, bool>? features = null,
            string? message = null)
        {
            var result = Result(state, now, error, key, request: request,
                features: features, limits: EmptyLimits(), requestPath: GetRequestPath(request.Product, Path.GetDirectoryName(Path.GetDirectoryName(path))));
            result.Override = deploymentOverride;
            result.OverridePath = path;
            result.Message = message;
            return result;
        }

        private static DeploymentOverrideRequest ParseOverrideRequest(string value)
        {
            if (string.IsNullOrWhiteSpace(value) || StrictUtf8.GetByteCount(value) > MaxArtifactBytes)
                throw new InvalidDataException("The unrestricted deployment request is empty or too large.");
            return JsonSerializer.Deserialize<DeploymentOverrideRequest>(value, DeploymentJson.CompactOptions)
                ?? throw new InvalidDataException("The unrestricted deployment request is empty.");
        }

        private static string? ValidateOverrideStructure(DeploymentOverrideRequest request)
        {
            if (request.Version != OverrideVersion) return "override.unsupported_version";
            if (!string.Equals(request.Mode, OverrideMode, StringComparison.Ordinal)) return "override.invalid_mode";
            if (!Guid.TryParseExact(request.DeployId, "N", out _)) return "override.invalid_deploy_id";
            try { request.Product = NormalizeCode(request.Product, nameof(request.Product)); }
            catch (ArgumentException) { return "override.invalid_product"; }
            try
            {
                if (request.Fingerprint.SafeBase64Decode().Length != 32) return "override.invalid_fingerprint";
            }
            catch (FormatException) { return "override.invalid_fingerprint"; }
            return null;
        }

        private static string ComputeOverrideFingerprint(DeploymentOverrideRequest request, string publicKey)
        {
            var canonical = string.Join("\n", request.Version, request.Mode, request.DeployId, request.Product,
                ComputePublicKeyHash(publicKey));
            using (var sha = SHA256.Create())
            {
                return Convert.ToBase64String(sha.ComputeHash(StrictUtf8.GetBytes(canonical))).SanitizeBase64();
            }
        }
    }
}
