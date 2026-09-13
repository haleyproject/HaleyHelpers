using System;
using System.Text.Json.Serialization;

namespace Haley.Internal
{
    internal sealed class DeploymentRecoveryRecord
    {
        [JsonPropertyName("artifact")]
        public string Artifact { get; set; } = string.Empty;

        [JsonPropertyName("reason")]
        public string Reason { get; set; } = string.Empty;

        [JsonPropertyName("firstSeen")]
        public DateTimeOffset FirstSeen { get; set; }
    }
}
