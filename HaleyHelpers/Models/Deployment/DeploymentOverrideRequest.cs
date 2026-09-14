using System.Text.Json.Serialization;

namespace Haley.Models
{
    public sealed class DeploymentOverrideRequest
    {
        [JsonPropertyName("version")]
        public int Version { get; set; }

        [JsonPropertyName("mode")]
        public string Mode { get; set; } = string.Empty;

        [JsonPropertyName("deploy-id")]
        public string DeployId { get; set; } = string.Empty;

        [JsonPropertyName("product")]
        public string Product { get; set; } = string.Empty;

        [JsonPropertyName("fingerprint")]
        public string Fingerprint { get; set; } = string.Empty;
    }
}
