using System;
using System.Collections.Generic;
using System.Text.Json;

namespace Haley.Models
{
    public sealed class DeploymentGrantOptions
    {
        public string LicensePath { get; set; } = string.Empty;
        public string Product { get; set; } = string.Empty;
        public string ProductVersion { get; set; } = string.Empty;
        public IReadOnlyCollection<string> Features { get; set; } = Array.Empty<string>();
        public IReadOnlyDictionary<string, DeploymentLimitDefinition> Limits { get; set; } = new Dictionary<string, DeploymentLimitDefinition>();
        public IReadOnlyDictionary<string, JsonElement> TrialLimits { get; set; } = new Dictionary<string, JsonElement>();
        public int TrialDays { get; set; }
        public int ExpiringDays { get; set; } = 30;
        public int RecoveryDays { get; set; } = 7;
        public string? PublicKeyPath { get; set; }
        public string? BaseDirectory { get; set; }
        public DateTimeOffset? NowUtc { get; set; }
    }
}
