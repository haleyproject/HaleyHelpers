using System;
using System.Collections.Generic;

namespace Haley.Models
{
    public sealed class DeploymentRequestInput
    {
        public string Product { get; set; } = string.Empty;
        public string ProductVersion { get; set; } = string.Empty;
        public IReadOnlyCollection<string> Features { get; set; } = Array.Empty<string>();
        public IReadOnlyDictionary<string, DeploymentLimitDefinition> Limits { get; set; } = new Dictionary<string, DeploymentLimitDefinition>();
        public string? BaseDirectory { get; set; }
        public string? DeploymentInfoLocation { get; set; }
        public string? LicensePath { get; set; }
        public DateTimeOffset? NowUtc { get; set; }
    }
}
