using System;
using System.Collections.Generic;
using System.Text.Json;
using Haley.Utils;

namespace Haley.Models
{
    public sealed class DeploymentGrantInput
    {
        public string RequestEnvelope { get; set; } = string.Empty;
        public string LicenseId { get; set; } = string.Empty;
        public string Customer { get; set; } = string.Empty;
        public MachineLockMode MachineLock { get; set; }
        public IReadOnlyDictionary<string, bool> Features { get; set; } = new Dictionary<string, bool>();
        public IReadOnlyDictionary<string, JsonElement> Limits { get; set; } = new Dictionary<string, JsonElement>();
        public DateTimeOffset IssuedUtc { get; set; }
        public int ValidityDays { get; set; }
        public int GraceDays { get; set; }
        public string PrivateKey { get; set; } = string.Empty;
        public string Key { get; set; } = RsaKeyNames.Default;
    }
}
