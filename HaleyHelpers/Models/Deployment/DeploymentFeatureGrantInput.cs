using Haley.Utils;
using System;
using System.Collections.Generic;
using System.Text.Json;

namespace Haley.Models
{
    public sealed class DeploymentFeatureGrantInput
    {
        public string RequestEnvelope { get; set; } = string.Empty;
        public string GrantId { get; set; } = string.Empty;
        public int Revision { get; set; } = 1;
        public MachineLockMode MachineLock { get; set; }
        public IReadOnlyCollection<string> Features { get; set; } = Array.Empty<string>();
        public IReadOnlyCollection<string> Perpetual { get; set; } = Array.Empty<string>();
        public int? PerpetualMaxMajor { get; set; }
        public IReadOnlyDictionary<string, JsonElement> Limits { get; set; } = new Dictionary<string, JsonElement>();
        public DateTimeOffset IssuedUtc { get; set; }
        public string PrivateKey { get; set; } = string.Empty;
        public string Key { get; set; } = RsaKeyNames.Default;
    }
}
