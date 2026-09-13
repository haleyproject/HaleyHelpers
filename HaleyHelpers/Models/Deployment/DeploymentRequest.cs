using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Haley.Models
{
    public sealed class DeploymentRequest
    {
        [JsonPropertyName("version")]
        public int Version { get; set; }

        [JsonPropertyName("deployId")]
        public string DeployId { get; set; } = string.Empty;

        [JsonPropertyName("created")]
        public DateTimeOffset Created { get; set; }

        [JsonPropertyName("deployment")]
        public string Deployment { get; set; } = string.Empty;

        [JsonPropertyName("product")]
        public string Product { get; set; } = string.Empty;

        [JsonPropertyName("productVersion")]
        public string ProductVersion { get; set; } = string.Empty;

        [JsonPropertyName("features")]
        public List<string> Features { get; set; } = new List<string>();

        [JsonPropertyName("availableLimits")]
        public List<string> AvailableLimits { get; set; } = new List<string>();

        [JsonPropertyName("machineEvidence")]
        public MachineEvidence MachineEvidence { get; set; } = new MachineEvidence();
    }
}
