using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace Haley.Models
{
    /// <summary>
    /// An evaluated deployment grant held in memory. Every question is answered against the supplied time, so a
    /// long-running host moves from valid to expiring, grace and expiry without rereading the license files.
    /// </summary>
    /// <remarks>
    /// Perpetual features stay available after the term ends unless the license itself is tampered, invalid or
    /// bound to another deployment or machine. Term features apply only while the term is active. A trial grants
    /// every compiled feature. A grant that was not yet valid when evaluated stays inactive until it is evaluated
    /// again (see <see cref="RefreshDueUtc"/>), because its deployment and machine checks have not run.
    /// </remarks>
    public sealed class LicenseSnapshot
    {
        private static readonly IReadOnlyDictionary<string, JsonElement> NoLimits = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        private readonly HashSet<string> _known;
        private readonly bool _allowPerpetual;

        public LicenseSnapshot(DeploymentGrantResult grant, IEnumerable<string> knownFeatures, int expiringDays)
        {
            Grant = grant ?? throw new ArgumentNullException(nameof(grant));
            if (knownFeatures == null) throw new ArgumentNullException(nameof(knownFeatures));
            if (expiringDays < 0 || expiringDays > 3650) throw new ArgumentOutOfRangeException(nameof(expiringDays));
            KnownFeatures = knownFeatures.Where(item => !string.IsNullOrWhiteSpace(item))
                .Distinct(StringComparer.Ordinal).OrderBy(item => item, StringComparer.Ordinal).ToArray();
            _known = new HashSet<string>(KnownFeatures, StringComparer.Ordinal);
            ExpiringDays = expiringDays;
            TermFeatures = Known(grant.TermFeatures);
            PerpetualFeatures = Known(grant.PerpetualFeatures);
            _allowPerpetual = grant.State is not DeploymentGrantState.TamperedRequest
                and not DeploymentGrantState.TamperedGrant
                and not DeploymentGrantState.InvalidRequest
                and not DeploymentGrantState.InvalidGrant
                and not DeploymentGrantState.InvalidDeployment
                and not DeploymentGrantState.MachineMismatch;
            IsOperational = grant.State is DeploymentGrantState.Trial
                    or DeploymentGrantState.Valid
                    or DeploymentGrantState.Expiring
                    or DeploymentGrantState.Grace
                || grant.IsRecoveryActive
                || grant.Features.Values.Any(enabled => enabled);
            IsUsable = IsOperational || grant.State == DeploymentGrantState.Expired;
            RefreshDueUtc = grant.State == DeploymentGrantState.NotYetValid ? grant.Payload?.NotBefore : null;
        }

        /// <summary>The verified evaluation this snapshot was built from.</summary>
        public DeploymentGrantResult Grant { get; }

        /// <summary>The product's compiled feature catalog.</summary>
        public IReadOnlyList<string> KnownFeatures { get; }

        public int ExpiringDays { get; }

        /// <summary>Term features named by the grant, for every known feature.</summary>
        public IReadOnlyDictionary<string, bool> TermFeatures { get; }

        /// <summary>Perpetual features named by the grant, for every known feature.</summary>
        public IReadOnlyDictionary<string, bool> PerpetualFeatures { get; }

        /// <summary>True when the grant permitted something when it was evaluated (a replacement must be operational).</summary>
        public bool IsOperational { get; }

        /// <summary>True when a host may start with this grant: operational, or expired with its metadata intact.</summary>
        public bool IsUsable { get; }

        /// <summary>When set, the grant must be evaluated again from this time (a grant that was not yet valid).</summary>
        public DateTimeOffset? RefreshDueUtc { get; }

        public LicenseState GetState(DateTimeOffset now)
        {
            var grant = Grant;
            if (grant.IsRecoveryActive)
            {
                if (grant.RecoveryEndsUtc is not { } recoveryEnd || now >= recoveryEnd) return LicenseState.Invalid;
                return grant.Payload != null && now >= GraceEnd(grant.Payload) ? LicenseState.Expired : LicenseState.Recovery;
            }

            switch (grant.State)
            {
                case DeploymentGrantState.Trial:
                    return grant.GraceEndsUtc is { } trialEnd && now < trialEnd ? LicenseState.Trial : LicenseState.TrialExpired;
                case DeploymentGrantState.TrialExpired:
                    return LicenseState.TrialExpired;
                case DeploymentGrantState.NotYetValid:
                    return LicenseState.NotYetValid;
                case DeploymentGrantState.Expired:
                    // Expired grants skipped the deployment and machine checks; a clock moved back never revives them.
                    return LicenseState.Expired;
                case DeploymentGrantState.Valid:
                case DeploymentGrantState.Expiring:
                case DeploymentGrantState.Grace:
                    var payload = grant.Payload;
                    if (payload == null) return LicenseState.Invalid;
                    if (now >= GraceEnd(payload)) return LicenseState.Expired;
                    if (now >= payload.Expires) return LicenseState.Grace;
                    return payload.Expires - now <= TimeSpan.FromDays(ExpiringDays) ? LicenseState.Expiring : LicenseState.Valid;
                default:
                    return LicenseState.Invalid;
            }
        }

        public static bool IsTermState(LicenseState state)
            => state is LicenseState.Trial or LicenseState.Valid or LicenseState.Expiring or LicenseState.Grace or LicenseState.Recovery;

        public bool IsTermActive(DateTimeOffset now) => IsTermState(GetState(now));

        public bool HasFeature(string feature, DateTimeOffset now)
            => !string.IsNullOrWhiteSpace(feature) && _known.Contains(feature) && Resolve(feature, GetState(now));

        public IReadOnlyDictionary<string, bool> GetFeatures(DateTimeOffset now)
        {
            var state = GetState(now);
            return KnownFeatures.ToDictionary(feature => feature, feature => Resolve(feature, state), StringComparer.Ordinal);
        }

        /// <summary>
        /// Limits usable now. An entitlement file keeps its limits after the term ends; limits carried by the license
        /// itself or by the trial apply only while the term is active. A rejected entitlement yields none.
        /// </summary>
        public IReadOnlyDictionary<string, JsonElement> GetLimits(DateTimeOffset now)
        {
            var grant = Grant;
            if (!string.IsNullOrWhiteSpace(grant.FeatureGrantError)) return NoLimits;
            if (grant.FeatureGrant == null && !IsTermActive(now)) return NoLimits;
            return grant.Limits;
        }

        public bool TryGetLimit(string code, DateTimeOffset now, out JsonElement value)
        {
            value = default;
            return !string.IsNullOrWhiteSpace(code) && GetLimits(now).TryGetValue(code, out value);
        }

        public bool TryGetLimit(string code, DateTimeOffset now, out long value)
        {
            value = 0;
            return TryGetLimit(code, now, out JsonElement limit)
                && limit.ValueKind == JsonValueKind.Number
                && limit.TryGetInt64(out value);
        }

        /// <summary>End of the current period: trial end, term expiry, grace end, recovery end or the start date.</summary>
        public DateTimeOffset? GetPeriodEndUtc(DateTimeOffset now)
        {
            var grant = Grant;
            var payload = grant.Payload;
            return GetState(now) switch
            {
                LicenseState.Trial or LicenseState.TrialExpired => grant.GraceEndsUtc,
                LicenseState.Recovery => grant.RecoveryEndsUtc,
                LicenseState.Valid or LicenseState.Expiring => payload?.Expires,
                LicenseState.Grace or LicenseState.Expired => payload == null ? grant.GraceEndsUtc : GraceEnd(payload),
                LicenseState.NotYetValid => payload?.NotBefore,
                _ => grant.IsRecoveryActive ? grant.RecoveryEndsUtc : null
            };
        }

        public int? GetDaysRemaining(DateTimeOffset now)
        {
            var end = GetPeriodEndUtc(now);
            return end.HasValue ? Math.Max(0, (int)Math.Ceiling((end.Value - now).TotalDays)) : (int?)null;
        }

        public LicenseStatus ToStatus(DateTimeOffset now)
        {
            var grant = Grant;
            var payload = grant.Payload;
            var request = grant.Request;
            var state = GetState(now);
            var days = GetDaysRemaining(now);
            return new LicenseStatus
            {
                State = state,
                CheckedUtc = now,
                LicenseId = payload?.LicenseId,
                Product = payload?.Product ?? request?.Product ?? grant.FeatureGrant?.Product,
                ProductVersion = payload?.ProductVersion ?? request?.ProductVersion,
                Customer = payload?.Customer,
                Deployment = payload?.Deployment ?? request?.Deployment,
                DeploymentId = payload?.DeployId ?? request?.DeployId,
                SigningKey = grant.Key,
                Issued = payload?.Issued,
                NotBefore = payload?.NotBefore,
                Expires = payload?.Expires,
                GraceEnds = payload == null ? grant.GraceEndsUtc : GraceEnd(payload),
                RecoveryEnds = grant.RecoveryEndsUtc,
                GraceDays = payload?.GraceDays,
                DaysRemaining = days,
                SignatureValid = payload != null && grant.State != DeploymentGrantState.TamperedGrant,
                TermActive = IsTermState(state),
                Features = KnownFeatures.ToDictionary(feature => feature, feature => Resolve(feature, state), StringComparer.Ordinal),
                TermFeatures = TermFeatures.ToDictionary(item => item.Key, item => item.Value, StringComparer.Ordinal),
                PerpetualFeatures = PerpetualFeatures.ToDictionary(item => item.Key, item => item.Value, StringComparer.Ordinal),
                Limits = GetLimits(now).ToDictionary(item => item.Key, item => item.Value, StringComparer.Ordinal),
                FeatureGrantId = grant.FeatureGrant?.GrantId,
                FeatureGrantRevision = grant.FeatureGrant?.Revision,
                FeatureGrantError = grant.FeatureGrantError,
                Error = grant.Error,
                Warnings = grant.Warnings.ToList(),
                Message = BuildMessage(state, days ?? 0),
                RequestPath = grant.RequestPath
            };
        }

        private bool Resolve(string feature, LicenseState state)
        {
            if (state == LicenseState.Trial) return true;
            return _allowPerpetual && PerpetualFeatures.TryGetValue(feature, out var perpetual) && perpetual
                || IsTermState(state) && TermFeatures.TryGetValue(feature, out var term) && term;
        }

        private IReadOnlyDictionary<string, bool> Known(IReadOnlyDictionary<string, bool> source)
            => KnownFeatures.ToDictionary(feature => feature,
                feature => source.TryGetValue(feature, out var enabled) && enabled, StringComparer.Ordinal);

        private DateTimeOffset GraceEnd(DeploymentGrantPayload payload)
            => Grant.GraceEndsUtc ?? payload.Expires.AddDays(payload.GraceDays);

        private string? BuildMessage(LicenseState state, int days)
        {
            var dayText = days + (days == 1 ? " day" : " days");
            return state switch
            {
                LicenseState.Recovery => "Deployment evidence is temporarily unavailable. Recovery access ends in " + dayText + ".",
                LicenseState.Trial => "Trial access ends in " + dayText + ". Issue a signed grant from the deployment request.",
                LicenseState.TrialExpired => "The trial has ended. Install a signed grant to restore licensed features.",
                LicenseState.NotYetValid => "The signed grant is not active yet.",
                LicenseState.Expiring => "The signed grant expires in " + dayText + ".",
                LicenseState.Grace => "The signed grant has expired. Grace access ends in " + dayText + ".",
                LicenseState.Expired when _allowPerpetual && PerpetualFeatures.Values.Any(enabled => enabled)
                    => "The grant and grace period have expired. Only perpetual features remain available.",
                LicenseState.Expired => "The grant and grace period have expired. Term features are disabled.",
                LicenseState.Invalid when !string.IsNullOrWhiteSpace(Grant.Error)
                    => "Deployment grant validation failed (" + Grant.Error + ").",
                LicenseState.Invalid => "The deployment grant is unusable.",
                _ => null
            };
        }
    }
}
