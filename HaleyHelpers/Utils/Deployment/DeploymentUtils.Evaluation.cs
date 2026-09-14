using Haley.Enums;
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
        public static DeploymentGrantResult EvaluateGrant(DeploymentGrantOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));
            var now = (options.NowUtc ?? DateTimeOffset.UtcNow).ToUniversalTime();
            var normalized = ValidateGrantOptions(options);
            var baseDirectory = string.IsNullOrWhiteSpace(normalized.BaseDirectory)
                ? AppContext.BaseDirectory
                : normalized.BaseDirectory!;
            var licensePath = ResolveLicensePath(normalized.LicensePath, baseDirectory);
            var requestPath = GetRequestPath(normalized.Product, baseDirectory);
            var localRequest = LoadRequest(new DeploymentRequestInput
            {
                Product = normalized.Product,
                ProductVersion = normalized.ProductVersion,
                Features = normalized.Features,
                BaseDirectory = baseDirectory,
                NowUtc = now
            });
            if (!localRequest.IsValid || localRequest.Request == null)
            {
                return Result(MapRequestFailure(localRequest.Error), now, localRequest.Error,
                    request: localRequest.Request, requestPath: localRequest.RequestPath ?? requestPath);
            }

            if (!File.Exists(licensePath))
            {
                var trialEnds = localRequest.Request.Created.AddDays(normalized.TrialDays);
                return Result(now < trialEnds ? DeploymentGrantState.Trial : DeploymentGrantState.TrialExpired,
                    now,
                    now < trialEnds ? null : "grant.trial_expired",
                    request: localRequest.Request,
                    features: KnownFeatures(normalized.Features, enabled: now < trialEnds),
                    limits: now < trialEnds ? CopyKnownLimits(normalized.TrialLimits, normalized.AvailableLimits) : EmptyLimits(),
                    graceEnds: trialEnds,
                    requestPath: localRequest.RequestPath ?? requestPath);
            }

            string artifact;
            try { artifact = ReadBoundedText(licensePath); }
            catch (Exception exception) when (IsExpectedFailure(exception))
            {
                return Result(DeploymentGrantState.InvalidGrant, now, "grant.artifact_invalid", requestPath: requestPath);
            }

            var verification = ValidateIssuerEnvelope(artifact, normalized.PublicKeyPath, baseDirectory);
            if (!verification.IsValid || string.IsNullOrWhiteSpace(verification.Payload))
            {
                return Result(DeploymentGrantState.TamperedGrant, now,
                    verification.Error ?? "grant.invalid_signature", key: verification.Key, requestPath: requestPath);
            }

            DeploymentGrantPayload payload;
            try
            {
                payload = JsonSerializer.Deserialize<DeploymentGrantPayload>(verification.Payload!, DeploymentJson.CompactOptions)
                    ?? throw new JsonException("Grant payload is empty.");
            }
            catch (JsonException)
            {
                return Result(DeploymentGrantState.InvalidGrant, now, "grant.invalid_json",
                    key: verification.Key, requestPath: requestPath);
            }

            var semanticError = ValidateGrantPayload(payload, normalized);
            if (semanticError != null)
            {
                var semanticState = semanticError == "grant.deployment_mismatch"
                    ? DeploymentGrantState.InvalidDeployment
                    : DeploymentGrantState.InvalidGrant;
                return Result(semanticState, now, semanticError, key: verification.Key, payload: payload, requestPath: requestPath);
            }

            var graceEnds = payload.Expires.AddDays(payload.GraceDays);
            if (now < payload.NotBefore)
                return Result(DeploymentGrantState.NotYetValid, now, "grant.not_yet_valid",
                    key: verification.Key, payload: payload, graceEnds: graceEnds, requestPath: requestPath);
            if (now >= graceEnds)
                return Result(DeploymentGrantState.Expired, now, "grant.expired",
                    key: verification.Key, payload: payload, graceEnds: graceEnds, requestPath: requestPath);

            var features = SelectKnownFeatures(payload.Features, normalized.Features);
            var limits = SelectKnownLimits(payload.Limits, normalized.AvailableLimits);
            var warnings = BuildWarnings(payload, normalized);
            var deployRequest = ToDeploymentRequest(payload);
            var deployDirectory = GetDeploymentDirectoryPath(baseDirectory);
            var privatePath = Path.Combine(deployDirectory, PrivateKeyFileName);
            var publicPath = Path.Combine(deployDirectory, PublicKeyFileName);
            string? publicKey = null;
            try
            {
                if (!File.Exists(publicPath) && File.Exists(privatePath))
                {
                    Directory.CreateDirectory(deployDirectory);
                    WriteAtomically(publicPath,
                        EncryptionUtils.ASymmetric.DerivePemPublicKey(ReadBoundedText(privatePath)), overwrite: false);
                }
                if (File.Exists(publicPath)) publicKey = ReadBoundedText(publicPath);
            }
            catch (Exception exception) when (IsExpectedFailure(exception))
            {
                publicKey = null;
            }

            if (string.IsNullOrWhiteSpace(publicKey))
            {
                return RecoveryResult(DeploymentGrantState.MissingVerifier, "grant.verifier_missing",
                    artifact, normalized, now, verification.Key, payload, deployRequest, features, limits, warnings, graceEnds, requestPath);
            }
            if (!ValidateDeployPrint(deployRequest, payload.DeployPrint, publicKey!))
            {
                return Result(DeploymentGrantState.InvalidDeployment, now, "grant.deployment_mismatch",
                    verification.Key, payload, deployRequest, EmptyFeatures(normalized.Features), EmptyLimits(), warnings, graceEnds, requestPath: requestPath);
            }

            var expectedEvidence = payload.MachineLock == MachineLockMode.Lite
                ? payload.MachineEvidence.Lite.Take(1).ToArray()
                : payload.MachineLock == MachineLockMode.Strong
                    ? payload.MachineEvidence.Strong.Take(2).ToArray()
                    : Array.Empty<MachineFingerprint>();
            foreach (var expected in expectedEvidence)
            {
                var current = AssetUtils.GetMachineFingerprint(expected.Source);
                if (current == null)
                {
                    return RecoveryResult(DeploymentGrantState.MachineEvidenceUnavailable, "grant.machine_evidence_unavailable",
                        artifact, normalized, now, verification.Key, payload, deployRequest, features, limits, warnings, graceEnds, requestPath);
                }
                if (!string.Equals(current.Fingerprint, expected.Fingerprint, StringComparison.Ordinal))
                {
                    return Result(DeploymentGrantState.MachineMismatch, now, "grant.machine_mismatch",
                        verification.Key, payload, deployRequest, EmptyFeatures(normalized.Features), EmptyLimits(), warnings, graceEnds, requestPath: requestPath);
                }
            }

            ClearRecovery(deployDirectory);
            var state = now >= payload.Expires
                ? DeploymentGrantState.Grace
                : payload.Expires - now <= TimeSpan.FromDays(normalized.ExpiringDays)
                    ? DeploymentGrantState.Expiring
                    : DeploymentGrantState.Valid;
            return Result(state, now, null, verification.Key, payload, deployRequest,
                features, limits, warnings, graceEnds, requestPath: requestPath);
        }

        private static DeploymentGrantOptions ValidateGrantOptions(DeploymentGrantOptions options)
        {
            if (options.TrialDays < 0 || options.TrialDays > 3650) throw new ArgumentOutOfRangeException(nameof(options.TrialDays));
            if (options.ExpiringDays < 0 || options.ExpiringDays > 3650) throw new ArgumentOutOfRangeException(nameof(options.ExpiringDays));
            if (options.RecoveryDays < 0 || options.RecoveryDays > 365) throw new ArgumentOutOfRangeException(nameof(options.RecoveryDays));
            var request = NormalizeInput(new DeploymentRequestInput
            {
                Product = options.Product,
                ProductVersion = options.ProductVersion,
                Features = options.Features,
                BaseDirectory = options.BaseDirectory,
                NowUtc = options.NowUtc
            });
            return new DeploymentGrantOptions
            {
                LicensePath = options.LicensePath?.Trim() ?? string.Empty,
                Product = request.Product,
                ProductVersion = request.ProductVersion,
                Features = request.Features,
                AvailableLimits = NormalizeCatalog(options.AvailableLimits),
                TrialLimits = CopyLimits(options.TrialLimits),
                TrialDays = options.TrialDays,
                ExpiringDays = options.ExpiringDays,
                RecoveryDays = options.RecoveryDays,
                PublicKeyPath = options.PublicKeyPath,
                BaseDirectory = options.BaseDirectory,
                NowUtc = options.NowUtc
            };
        }

        private static RsaVerificationResult ValidateIssuerEnvelope(string artifact, string? publicKeyPath, string baseDirectory)
        {
            if (string.IsNullOrWhiteSpace(publicKeyPath))
                return EncryptionUtils.ASymmetric.Envelope.Validate(artifact);
            try
            {
                var path = ResolvePath(publicKeyPath!.Trim(), baseDirectory);
                return EncryptionUtils.ASymmetric.Envelope.Validate(artifact, ReadBoundedText(path));
            }
            catch (Exception exception) when (IsExpectedFailure(exception))
            {
                return new RsaVerificationResult { IsValid = false, Error = "grant.public_key_unavailable" };
            }
        }

        private static string? ValidateGrantPayload(DeploymentGrantPayload payload, DeploymentGrantOptions options)
        {
            if (payload.Version != SupportedVersion) return "grant.unsupported_version";
            if (string.IsNullOrWhiteSpace(payload.LicenseId) || string.IsNullOrWhiteSpace(payload.Customer)) return "grant.required_fields_missing";
            if (!string.Equals(payload.Product, options.Product, StringComparison.Ordinal)) return "grant.product_mismatch";
            if (!Guid.TryParseExact(payload.DeployId, "N", out _)) return "grant.invalid_deploy_id";
            if (!string.Equals(payload.Deployment, payload.DeployId, StringComparison.Ordinal)) return "grant.deployment_mismatch";
            if (payload.RequestCreated == default || string.IsNullOrWhiteSpace(payload.DeployPrint)) return "grant.request_proof_missing";
            if (payload.Issued == default || payload.NotBefore < payload.Issued || payload.Expires <= payload.NotBefore) return "grant.invalid_dates";
            if (payload.GraceDays < 0 || payload.GraceDays > 3650) return "grant.invalid_grace";
            try { _ = payload.Expires.AddDays(payload.GraceDays); }
            catch (ArgumentOutOfRangeException) { return "grant.invalid_dates"; }
            if (!Enum.IsDefined(typeof(MachineLockMode), payload.MachineLock)) return "grant.machine_mode_invalid";
            if (payload.MachineEvidence == null) return "grant.machine_evidence_missing";
            if (payload.MachineLock == MachineLockMode.Lite && payload.MachineEvidence.Lite.Count < 1) return "grant.machine_evidence_missing";
            if (payload.MachineLock == MachineLockMode.Strong && payload.MachineEvidence.Strong.Count < 2) return "grant.machine_evidence_missing";
            payload.Features = payload.Features == null
                ? new Dictionary<string, bool>(StringComparer.Ordinal)
                : new Dictionary<string, bool>(payload.Features, StringComparer.Ordinal);
            payload.Limits = payload.Limits == null
                ? new Dictionary<string, long>(StringComparer.Ordinal)
                : new Dictionary<string, long>(payload.Limits, StringComparer.Ordinal);
            if (payload.Limits.Any(item => item.Value < 0)) return "grant.invalid_limit";
            return null;
        }

        private static DeploymentRequest ToDeploymentRequest(DeploymentGrantPayload payload)
        {
            return new DeploymentRequest
            {
                Version = payload.Version,
                DeployId = payload.DeployId,
                Created = payload.RequestCreated,
                Deployment = payload.Deployment,
                Product = payload.Product,
                ProductVersion = payload.ProductVersion,
                MachineEvidence = payload.MachineEvidence,
                Features = payload.Features.Keys.OrderBy(item => item, StringComparer.Ordinal).ToList(),
                AvailableLimits = new List<string>()
            };
        }

        private static IReadOnlyList<string> BuildWarnings(DeploymentGrantPayload payload, DeploymentGrantOptions options)
        {
            var result = new List<string>();
            if (!string.Equals(payload.ProductVersion, options.ProductVersion, StringComparison.Ordinal))
                result.Add("grant.product_version_differs");
            foreach (var feature in payload.Features.Keys.Except(options.Features, StringComparer.Ordinal))
                result.Add("grant.unknown_feature:" + feature);
            foreach (var limit in payload.Limits.Keys.Except(options.AvailableLimits, StringComparer.Ordinal))
                result.Add("grant.unknown_limit:" + limit);
            return result;
        }

        private static Dictionary<string, bool> KnownFeatures(IEnumerable<string> known, bool enabled)
            => known.ToDictionary(item => item, _ => enabled, StringComparer.Ordinal);

        private static Dictionary<string, bool> SelectKnownFeatures(
            IReadOnlyDictionary<string, bool> supplied, IEnumerable<string> known)
            => known.ToDictionary(item => item,
                item => supplied.TryGetValue(item, out var enabled) && enabled, StringComparer.Ordinal);

        private static Dictionary<string, bool> EmptyFeatures(IEnumerable<string> known)
            => KnownFeatures(known, enabled: false);

        private static Dictionary<string, long> SelectKnownLimits(
            IReadOnlyDictionary<string, long> supplied, IEnumerable<string> known)
            => known.Where(supplied.ContainsKey).ToDictionary(item => item, item => supplied[item], StringComparer.Ordinal);

        private static Dictionary<string, long> CopyKnownLimits(
            IReadOnlyDictionary<string, long> supplied, IEnumerable<string> known)
            => SelectKnownLimits(supplied, known);

        private static Dictionary<string, long> EmptyLimits() => new Dictionary<string, long>(StringComparer.Ordinal);

        private static DeploymentGrantState MapRequestFailure(string? error)
        {
            if (string.Equals(error, "request.invalid_deploy_print", StringComparison.Ordinal)) return DeploymentGrantState.TamperedRequest;
            if (string.Equals(error, "request.invalid", StringComparison.Ordinal)
                || string.Equals(error, "request.invalid_fields", StringComparison.Ordinal)) return DeploymentGrantState.InvalidRequest;
            return DeploymentGrantState.RequestUnavailable;
        }

        private static DeploymentGrantResult RecoveryResult(
            DeploymentGrantState state,
            string reason,
            string artifact,
            DeploymentGrantOptions options,
            DateTimeOffset now,
            string? key,
            DeploymentGrantPayload payload,
            DeploymentRequest request,
            IReadOnlyDictionary<string, bool> features,
            IReadOnlyDictionary<string, long> limits,
            IReadOnlyList<string> warnings,
            DateTimeOffset graceEnds,
            string requestPath)
        {
            var directory = GetDeploymentDirectoryPath(options.BaseDirectory);
            var recoveryPath = Path.Combine(directory, RecoveryFileName);
            var digest = artifact.ComputeHash(HashMethod.Sha256, encodeBase64: false);
            DeploymentRecoveryRecord? record = null;
            try
            {
                if (File.Exists(recoveryPath))
                    record = JsonSerializer.Deserialize<DeploymentRecoveryRecord>(ReadBoundedText(recoveryPath), DeploymentJson.CompactOptions);
                if (record == null || !string.Equals(record.Artifact, digest, StringComparison.Ordinal)
                    || !string.Equals(record.Reason, reason, StringComparison.Ordinal))
                {
                    record = new DeploymentRecoveryRecord { Artifact = digest, Reason = reason, FirstSeen = now };
                    WriteAtomically(recoveryPath, JsonSerializer.Serialize(record, DeploymentJson.Options), overwrite: true);
                }
            }
            catch (Exception exception) when (IsExpectedFailure(exception))
            {
                record = null;
            }

            var recoveryEnds = record?.FirstSeen.AddDays(options.RecoveryDays);
            var active = recoveryEnds.HasValue && now < recoveryEnds.Value;
            return Result(state, now, active ? reason : reason + "_recovery_expired", key, payload, request,
                active ? features : EmptyFeatures(options.Features), active ? limits : EmptyLimits(), warnings,
                graceEnds, recoveryEnds, active, requestPath);
        }

        private static void ClearRecovery(string deployDirectory)
        {
            try
            {
                var path = Path.Combine(deployDirectory, RecoveryFileName);
                if (File.Exists(path)) File.Delete(path);
            }
            catch (Exception exception) when (IsExpectedFailure(exception)) { }
        }

        private static DeploymentGrantResult Result(
            DeploymentGrantState state,
            DateTimeOffset now,
            string? error,
            string? key = null,
            DeploymentGrantPayload? payload = null,
            DeploymentRequest? request = null,
            IReadOnlyDictionary<string, bool>? features = null,
            IReadOnlyDictionary<string, long>? limits = null,
            IReadOnlyList<string>? warnings = null,
            DateTimeOffset? graceEnds = null,
            DateTimeOffset? recoveryEnds = null,
            bool recoveryActive = false,
            string? requestPath = null)
        {
            return new DeploymentGrantResult
            {
                State = state,
                Error = error,
                Key = key,
                Payload = payload,
                Request = request,
                Features = features ?? new Dictionary<string, bool>(),
                Limits = limits ?? new Dictionary<string, long>(),
                Warnings = warnings ?? Array.Empty<string>(),
                CheckedUtc = now,
                GraceEndsUtc = graceEnds,
                RecoveryEndsUtc = recoveryEnds,
                IsRecoveryActive = recoveryActive,
                RequestPath = requestPath
            };
        }

        private static string ResolvePath(string path, string baseDirectory)
        {
            return Path.IsPathRooted(path)
                ? Path.GetFullPath(path)
                : Path.GetFullPath(Path.Combine(Path.GetFullPath(baseDirectory), path));
        }
    }
}
