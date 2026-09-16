using Haley.Internal;
using Haley.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace Haley.Utils
{
    public static partial class DeploymentUtils
    {
        public const string FeatureGrantFileName = "features.fea";
        private const int FeatureGrantVersion = 1;
        private const string FeatureWildcard = "*";

        public static string PrepareFeatureGrant(DeploymentFeatureGrantInput input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            var decoded = DecodeRequestEnvelope(input.RequestEnvelope);
            if (!decoded.IsValid || decoded.Request == null)
                throw new ArgumentException("The deployment request is invalid (" + (decoded.Error ?? "request.invalid") + ").", nameof(input));
            if (decoded.Request.Version != SupportedVersion)
                throw new ArgumentException("The deployment request must be renewed before feature entitlement can be issued.", nameof(input));
            if (input.Revision < 1) throw new ArgumentOutOfRangeException(nameof(input.Revision));
            if (input.PerpetualMaxMajor is < 0) throw new ArgumentOutOfRangeException(nameof(input.PerpetualMaxMajor));
            if (!Enum.IsDefined(typeof(MachineLockMode), input.MachineLock))
                throw new ArgumentOutOfRangeException(nameof(input.MachineLock));
            if (input.IssuedUtc == default) throw new ArgumentException("The issue time is required.", nameof(input.IssuedUtc));
            if (string.IsNullOrWhiteSpace(input.PrivateKey))
                throw new ArgumentException("The issuer private key is required.", nameof(input));
            if (!EncryptionUtils.ASymmetric.Envelope.IsValidKeyName(input.Key))
                throw new ArgumentException("The issuer key name is invalid.", nameof(input));

            var request = decoded.Request;
            var features = NormalizeFeatureSelection(input.Features, nameof(input.Features));
            var perpetual = NormalizeFeatureSelection(input.Perpetual, nameof(input.Perpetual));
            if (perpetual.Contains(FeatureWildcard, StringComparer.Ordinal) && features.Count > 0)
                throw new ArgumentException("Term features are redundant when every feature is perpetual.", nameof(input));
            if (!features.Contains(FeatureWildcard, StringComparer.Ordinal))
            {
                var overlap = features.Intersect(perpetual, StringComparer.Ordinal).ToArray();
                if (overlap.Length > 0)
                    throw new ArgumentException("A feature cannot be both term-bound and perpetual: " + string.Join(", ", overlap) + ".", nameof(input));
            }

            var limits = NormalizeLimitValues(input.Limits);
            RequireExactCatalog(request.Limits.Keys, limits.Keys, "limit");
            ValidateLimitTypes(request.Limits, limits);
            ValidateSelectedMachineEvidence(request.MachineEvidence, input.MachineLock);

            var payload = new DeploymentFeatureGrantPayload
            {
                Version = FeatureGrantVersion,
                GrantId = NormalizeCode(input.GrantId, nameof(input.GrantId)),
                Revision = input.Revision,
                Product = request.Product,
                ProductVersion = request.ProductVersion,
                DeployId = request.DeployId,
                Binding = input.RequestEnvelope,
                MachineLock = input.MachineLock,
                Issued = input.IssuedUtc.ToUniversalTime(),
                Features = features,
                Perpetual = perpetual,
                PerpetualMaxMajor = input.PerpetualMaxMajor,
                Limits = limits
            };
            var json = JsonSerializer.Serialize(payload, DeploymentJson.CompactOptions);
            return EncryptionUtils.ASymmetric.Envelope.Prepare(json, input.PrivateKey, input.Key);
        }

        public static string GetFeatureGrantPath(string? baseDirectory = null)
            => GetFeatureGrantPath(baseDirectory, null);

        public static string GetFeatureGrantPath(string? baseDirectory, string? deploymentInfoLocation)
            => Path.Combine(GetDeploymentDirectoryPath(baseDirectory, deploymentInfoLocation), FeatureGrantFileName);

        private static DeploymentGrantResult ApplyFeatureGrant(DeploymentGrantOptions options, DeploymentGrantResult result)
        {
            var path = GetFeatureGrantPath(options.BaseDirectory, options.DeploymentInfoLocation);
            result.FeatureGrantPath = path;
            var legacyFeatures = result.Features;
            var legacyLimits = result.Limits;
            if (!File.Exists(path))
            {
                result.TermFeatures = legacyFeatures;
                result.PerpetualFeatures = EmptyFeatures(options.Features);
                if (!IsTermActive(result))
                {
                    result.Features = EmptyFeatures(options.Features);
                    result.Limits = EmptyLimits();
                }
                if (result.Payload != null && (result.Payload.Features == null || result.Payload.Features.Count == 0))
                {
                    result.FeatureGrantError = "feature.missing";
                    result.Warnings = AppendWarning(result.Warnings, "feature.missing");
                }
                return result;
            }

            // Unreadable machine evidence already opened a bounded recovery window for the signed license;
            // the feature entitlement bound to the same deployment shares that window instead of failing on its own.
            var evidenceRecovery = result.IsRecoveryActive && result.State == DeploymentGrantState.MachineEvidenceUnavailable;
            var evaluation = EvaluateFeatureGrant(options, result.Request, path, evidenceRecovery);
            result.FeatureGrant = evaluation.Payload;
            result.FeatureGrantError = evaluation.Error;
            result.TermFeatures = evaluation.TermFeatures;
            result.PerpetualFeatures = evaluation.PerpetualFeatures;
            result.Warnings = result.Warnings.Concat(evaluation.Warnings).Distinct(StringComparer.Ordinal).ToArray();
            if (!evaluation.IsValid)
            {
                result.Features = EmptyFeatures(options.Features);
                result.Limits = EmptyLimits();
                return result;
            }

            var allowTerm = IsTermActive(result);
            var allowPerpetual = result.State is not DeploymentGrantState.TamperedRequest
                and not DeploymentGrantState.TamperedGrant
                and not DeploymentGrantState.InvalidRequest
                and not DeploymentGrantState.InvalidGrant
                and not DeploymentGrantState.InvalidDeployment
                and not DeploymentGrantState.MachineMismatch;
            var effective = options.Features.ToDictionary(
                feature => feature,
                feature => allowPerpetual && evaluation.PerpetualFeatures.TryGetValue(feature, out var permanent) && permanent
                    || allowTerm && evaluation.TermFeatures.TryGetValue(feature, out var term) && term,
                StringComparer.Ordinal);
            if (result.State == DeploymentGrantState.Trial)
                effective = KnownFeatures(options.Features, enabled: true);
            result.Features = effective;
            // A tampered, mismatched or invalid license withholds the entitlement's limits as well as its features.
            result.Limits = allowTerm || allowPerpetual ? evaluation.Limits : EmptyLimits();
            return result;
        }

        private static bool IsTermActive(DeploymentGrantResult result)
            => result.State is DeploymentGrantState.Trial
                or DeploymentGrantState.Valid
                or DeploymentGrantState.Expiring
                or DeploymentGrantState.Grace
                || result.IsRecoveryActive;

        private static FeatureGrantEvaluation EvaluateFeatureGrant(
            DeploymentGrantOptions options,
            DeploymentRequest? localRequest,
            string path,
            bool evidenceRecovery)
        {
            var empty = EmptyFeatures(options.Features);
            if (localRequest == null)
                return FeatureGrantEvaluation.Failure("feature.request_unavailable", path, empty);
            try
            {
                var baseDirectory = string.IsNullOrWhiteSpace(options.BaseDirectory) ? AppContext.BaseDirectory : options.BaseDirectory!;
                var verification = ValidateIssuerEnvelope(ReadBoundedText(path), options.PublicKeyPath, baseDirectory);
                if (!verification.IsValid || string.IsNullOrWhiteSpace(verification.Payload))
                    return FeatureGrantEvaluation.Failure(verification.Error ?? "feature.invalid_signature", path, empty);
                var payload = JsonSerializer.Deserialize<DeploymentFeatureGrantPayload>(verification.Payload!, DeploymentJson.CompactOptions)
                    ?? throw new JsonException("Feature entitlement is empty.");
                var structureError = ValidateFeaturePayload(payload);
                if (structureError != null) return FeatureGrantEvaluation.Failure(structureError, path, empty, payload);
                if (!string.Equals(payload.Product, options.Product, StringComparison.Ordinal))
                    return FeatureGrantEvaluation.Failure("feature.product_mismatch", path, empty, payload);
                if (!string.Equals(payload.DeployId, localRequest.DeployId, StringComparison.Ordinal))
                    return FeatureGrantEvaluation.Failure("feature.deployment_mismatch", path, empty, payload);

                var deployDirectory = GetDeploymentDirectoryPath(options.BaseDirectory, options.DeploymentInfoLocation);
                var publicPath = Path.Combine(deployDirectory, PublicKeyFileName);
                if (!File.Exists(publicPath))
                    return FeatureGrantEvaluation.Failure("feature.deployment_key_missing", path, empty, payload);
                var bound = ValidateRequestEnvelope(payload.Binding, ReadBoundedText(publicPath));
                if (!bound.IsValid || bound.Request == null)
                    return FeatureGrantEvaluation.Failure("feature.invalid_deployment_binding", path, empty, payload);
                if (!string.Equals(bound.Request.DeployId, payload.DeployId, StringComparison.Ordinal)
                    || !string.Equals(bound.Request.Product, payload.Product, StringComparison.Ordinal))
                    return FeatureGrantEvaluation.Failure("feature.binding_mismatch", path, empty, payload);

                var machineError = ValidateCurrentMachine(bound.Request.MachineEvidence, payload.MachineLock);
                var machineRecovery = evidenceRecovery && machineError == "machine_evidence_unavailable";
                if (machineError != null && !machineRecovery)
                    return FeatureGrantEvaluation.Failure("feature." + machineError, path, empty, payload);
                try
                {
                    payload.Limits = NormalizeLimitValues(payload.Limits);
                }
                catch (ArgumentException)
                {
                    return FeatureGrantEvaluation.Failure("feature.invalid_limits", path, empty, payload);
                }

                var term = ExpandFeatureSelection(payload.Features, options.Features);
                var perpetual = ExpandFeatureSelection(payload.Perpetual, options.Features);
                var warnings = new List<string>();
                if (machineRecovery) warnings.Add("feature.machine_evidence_recovery");
                if (!string.Equals(payload.ProductVersion, options.ProductVersion, StringComparison.Ordinal))
                    warnings.Add("feature.product_version_differs");
                foreach (var feature in payload.Features.Concat(payload.Perpetual)
                    .Where(feature => feature != FeatureWildcard)
                    .Except(options.Features, StringComparer.Ordinal))
                    warnings.Add("feature.unknown:" + feature);
                if (payload.PerpetualMaxMajor.HasValue)
                {
                    if (!TryGetMajorVersion(options.ProductVersion, out var major))
                    {
                        perpetual = EmptyFeatures(options.Features);
                        warnings.Add("feature.product_major_unavailable");
                    }
                    else if (major > payload.PerpetualMaxMajor.Value)
                    {
                        perpetual = EmptyFeatures(options.Features);
                        warnings.Add("feature.perpetual_major_exceeded");
                    }
                }

                return FeatureGrantEvaluation.Success(payload, path, term, perpetual,
                    SelectKnownLimits(payload.Limits, options.Limits), warnings);
            }
            catch (Exception exception) when (IsExpectedFailure(exception))
            {
                return FeatureGrantEvaluation.Failure("feature.artifact_invalid", path, empty, message: exception.Message);
            }
        }

        private static string? ValidateFeaturePayload(DeploymentFeatureGrantPayload payload)
        {
            if (payload.Version != FeatureGrantVersion) return "feature.unsupported_version";
            if (payload.Revision < 1) return "feature.invalid_revision";
            if (payload.Issued == default) return "feature.issued_required";
            if (!Guid.TryParseExact(payload.DeployId, "N", out _)) return "feature.invalid_deploy_id";
            if (string.IsNullOrWhiteSpace(payload.Binding)) return "feature.binding_required";
            if (payload.PerpetualMaxMajor is < 0) return "feature.invalid_perpetual_major";
            if (!Enum.IsDefined(typeof(MachineLockMode), payload.MachineLock)) return "feature.machine_mode_invalid";
            try
            {
                payload.GrantId = NormalizeCode(payload.GrantId, nameof(payload.GrantId));
                payload.Product = NormalizeCode(payload.Product, nameof(payload.Product));
                payload.ProductVersion = NormalizeText(payload.ProductVersion, nameof(payload.ProductVersion), 64);
                payload.Features = NormalizeFeatureSelection(payload.Features, nameof(payload.Features));
                payload.Perpetual = NormalizeFeatureSelection(payload.Perpetual, nameof(payload.Perpetual));
                if (payload.Perpetual.Contains(FeatureWildcard, StringComparer.Ordinal) && payload.Features.Count > 0)
                    return "feature.redundant_term_features";
                if (!payload.Features.Contains(FeatureWildcard, StringComparer.Ordinal)
                    && payload.Features.Intersect(payload.Perpetual, StringComparer.Ordinal).Any())
                    return "feature.overlapping_assignments";
            }
            catch (ArgumentException)
            {
                return "feature.invalid_fields";
            }
            return null;
        }

        private static List<string> NormalizeFeatureSelection(IEnumerable<string>? values, string name)
        {
            var result = (values ?? Array.Empty<string>())
                .Select(value => string.Equals(value?.Trim(), FeatureWildcard, StringComparison.Ordinal)
                    ? FeatureWildcard
                    : NormalizeCode(value ?? string.Empty, name))
                .Distinct(StringComparer.Ordinal)
                .OrderBy(value => value, StringComparer.Ordinal)
                .ToList();
            if (result.Contains(FeatureWildcard, StringComparer.Ordinal) && result.Count != 1)
                throw new ArgumentException("The feature wildcard cannot be combined with named features.", name);
            return result;
        }

        private static Dictionary<string, bool> ExpandFeatureSelection(
            IReadOnlyCollection<string> selection,
            IEnumerable<string> known)
        {
            var all = selection.Contains(FeatureWildcard, StringComparer.Ordinal);
            var selected = new HashSet<string>(selection, StringComparer.Ordinal);
            return known.ToDictionary(feature => feature, feature => all || selected.Contains(feature), StringComparer.Ordinal);
        }

        private static string? ValidateCurrentMachine(MachineEvidence evidence, MachineLockMode mode)
        {
            if (mode == MachineLockMode.None) return null;
            var expected = mode == MachineLockMode.Lite
                ? evidence.Lite.Take(1).ToArray()
                : evidence.Strong.Take(2).ToArray();
            if (expected.Length < (mode == MachineLockMode.Lite ? 1 : 2)) return "machine_evidence_missing";
            if (expected.Any(item => !string.IsNullOrWhiteSpace(item.Source)))
            {
                foreach (var item in expected)
                {
                    var current = AssetUtils.GetMachineFingerprint(item.Source);
                    if (current == null) return "machine_evidence_unavailable";
                    if (!string.Equals(current.Fingerprint, item.Fingerprint, StringComparison.Ordinal)) return "machine_mismatch";
                }
                return null;
            }

            var currentEvidence = AssetUtils.GetMachineEvidence(mode);
            if (!currentEvidence.IsAvailable) return "machine_evidence_unavailable";
            return expected.Select(item => item.Fingerprint).OrderBy(item => item, StringComparer.Ordinal)
                .SequenceEqual(currentEvidence.Fingerprints.Select(item => item.Fingerprint).OrderBy(item => item, StringComparer.Ordinal), StringComparer.Ordinal)
                ? null
                : "machine_mismatch";
        }

        private static bool TryGetMajorVersion(string value, out int major)
        {
            major = 0;
            var first = value.Split(new[] { '.', '-', '+' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            return int.TryParse(first, out major) && major >= 0;
        }

        private static IReadOnlyList<string> AppendWarning(IReadOnlyList<string> warnings, string warning)
            => warnings.Concat(new[] { warning }).Distinct(StringComparer.Ordinal).ToArray();

        private sealed class FeatureGrantEvaluation
        {
            internal bool IsValid { get; private set; }
            internal string? Error { get; private set; }
            internal string? Message { get; private set; }
            internal string Path { get; private set; } = string.Empty;
            internal DeploymentFeatureGrantPayload? Payload { get; private set; }
            internal IReadOnlyDictionary<string, bool> TermFeatures { get; private set; } = new Dictionary<string, bool>();
            internal IReadOnlyDictionary<string, bool> PerpetualFeatures { get; private set; } = new Dictionary<string, bool>();
            internal IReadOnlyDictionary<string, JsonElement> Limits { get; private set; } = new Dictionary<string, JsonElement>();
            internal IReadOnlyList<string> Warnings { get; private set; } = Array.Empty<string>();

            internal static FeatureGrantEvaluation Failure(
                string error,
                string path,
                IReadOnlyDictionary<string, bool> empty,
                DeploymentFeatureGrantPayload? payload = null,
                string? message = null)
                => new FeatureGrantEvaluation
                {
                    Error = error,
                    Message = message,
                    Path = path,
                    Payload = payload,
                    TermFeatures = empty,
                    PerpetualFeatures = empty,
                    Warnings = new[] { error }
                };

            internal static FeatureGrantEvaluation Success(
                DeploymentFeatureGrantPayload payload,
                string path,
                IReadOnlyDictionary<string, bool> term,
                IReadOnlyDictionary<string, bool> perpetual,
                IReadOnlyDictionary<string, JsonElement> limits,
                IReadOnlyList<string> warnings)
                => new FeatureGrantEvaluation
                {
                    IsValid = true,
                    Path = path,
                    Payload = payload,
                    TermFeatures = term,
                    PerpetualFeatures = perpetual,
                    Limits = limits,
                    Warnings = warnings
                };
        }
    }
}
