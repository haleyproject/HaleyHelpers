using System;
using System.Collections.Generic;

namespace Haley.Models
{
    public sealed class DeploymentGrantOptions
    {
        public string LicensePath { get; set; } = string.Empty;
        public string Product { get; set; } = string.Empty;
        public string ProductVersion { get; set; } = string.Empty;
        public string Deployment { get; set; } = string.Empty;
        public IReadOnlyCollection<string> Features { get; set; } = Array.Empty<string>();
        public IReadOnlyCollection<string> AvailableLimits { get; set; } = Array.Empty<string>();
        public IReadOnlyDictionary<string, long> TrialLimits { get; set; } = new Dictionary<string, long>();
        public MachineLockMode RequestMachineEvidenceMode { get; set; }
        public int TrialDays { get; set; }
        public int ExpiringDays { get; set; } = 30;
        public int RecoveryDays { get; set; } = 7;
        public string? PublicKeyPath { get; set; }
        public string? BaseDirectory { get; set; }
        public DateTimeOffset? NowUtc { get; set; }
    }
}
