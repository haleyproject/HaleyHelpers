using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Haley.Models
{
    public sealed class DeploymentFeatureGrantPayload
    {
        [JsonPropertyName("version")]
        public int Version { get; set; }

        [JsonPropertyName("grantId")]
        public string GrantId { get; set; } = string.Empty;

        [JsonPropertyName("revision")]
        public int Revision { get; set; }

        [JsonPropertyName("product")]
        public string Product { get; set; } = string.Empty;

        [JsonPropertyName("productVersion")]
        public string ProductVersion { get; set; } = string.Empty;

        [JsonPropertyName("deployId")]
        public string DeployId { get; set; } = string.Empty;

        [JsonPropertyName("binding")]
        public string Binding { get; set; } = string.Empty;

        [JsonPropertyName("machineLock")]
        public MachineLockMode MachineLock { get; set; }

        [JsonPropertyName("issued")]
        public DateTimeOffset Issued { get; set; }

        [JsonPropertyName("features")]
        public List<string> Features { get; set; } = new List<string>();

        [JsonPropertyName("perpetual")]
        public List<string> Perpetual { get; set; } = new List<string>();

        [JsonPropertyName("perpetualMaxMajor")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public int? PerpetualMaxMajor { get; set; }

        [JsonPropertyName("limits")]
        public Dictionary<string, JsonElement> Limits { get; set; } = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
    }
}
