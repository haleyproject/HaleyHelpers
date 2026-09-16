using System;
using System.Collections.Generic;
using System.Text.Json;

namespace Haley.Models
{
    /// <summary>
    /// Safe projection of a license snapshot at one moment. Contains no artifact, signature, key material or machine
    /// identifier, so it can be shown to administrators.
    /// </summary>
    public sealed class LicenseStatus
    {
        public LicenseState State { get; set; }
        public DateTimeOffset CheckedUtc { get; set; }
        public string? LicenseId { get; set; }
        public string? Product { get; set; }
        public string? ProductVersion { get; set; }
        public string? Customer { get; set; }
        public string? Deployment { get; set; }
        public string? DeploymentId { get; set; }
        /// <summary>Name of the issuer key that signed the grant.</summary>
        public string? SigningKey { get; set; }
        public DateTimeOffset? Issued { get; set; }
        public DateTimeOffset? NotBefore { get; set; }
        public DateTimeOffset? Expires { get; set; }
        /// <summary>End of grace for a signed grant, or the end of the trial.</summary>
        public DateTimeOffset? GraceEnds { get; set; }
        public DateTimeOffset? RecoveryEnds { get; set; }
        public int? GraceDays { get; set; }
        /// <summary>Whole days until the current period (trial, term, grace or recovery) ends.</summary>
        public int? DaysRemaining { get; set; }
        public bool SignatureValid { get; set; }
        /// <summary>True while term features apply: trial, valid, expiring, grace or recovery.</summary>
        public bool TermActive { get; set; }
        /// <summary>Features usable now: perpetual features plus term features while the term is active.</summary>
        public Dictionary<string, bool> Features { get; set; } = new Dictionary<string, bool>(StringComparer.Ordinal);
        public Dictionary<string, bool> TermFeatures { get; set; } = new Dictionary<string, bool>(StringComparer.Ordinal);
        public Dictionary<string, bool> PerpetualFeatures { get; set; } = new Dictionary<string, bool>(StringComparer.Ordinal);
        /// <summary>Limits usable now.</summary>
        public Dictionary<string, JsonElement> Limits { get; set; } = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        public string? FeatureGrantId { get; set; }
        public int? FeatureGrantRevision { get; set; }
        public string? FeatureGrantError { get; set; }
        /// <summary>Stable evaluation error code, such as <c>grant.expired</c>.</summary>
        public string? Error { get; set; }
        /// <summary>Stable warning codes, such as <c>grant.product_version_differs</c>.</summary>
        public List<string> Warnings { get; set; } = new List<string>();
        /// <summary>One human-readable line describing the state, when it needs attention.</summary>
        public string? Message { get; set; }
        public string? RequestPath { get; set; }

        public bool HasFeature(string feature)
            => !string.IsNullOrWhiteSpace(feature) && Features.TryGetValue(feature, out var enabled) && enabled;

        public bool TryGetLimit(string code, out long value)
        {
            value = 0;
            return !string.IsNullOrWhiteSpace(code)
                && Limits.TryGetValue(code, out var limit)
                && limit.ValueKind == JsonValueKind.Number
                && limit.TryGetInt64(out value);
        }
    }
}
